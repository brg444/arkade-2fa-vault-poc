package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/arkade-os/emulator/poc/2fa-vault/fixture"
)

const maxJSONBody = 1 << 20
const EnrollmentTokenHeader = "X-Vault-Enrollment-Token"

const (
	publishOperationTimeout = 55 * time.Second
	serverWriteTimeout      = 75 * time.Second
)

// NewServer wraps h with the POC listen timeouts.
func NewServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// A publish operation has its own 55-second deadline. Leave a bounded
		// response margin above it for error serialization and slow clients.
		WriteTimeout: serverWriteTimeout,
		IdleTimeout:  60 * time.Second,
	}
}

// ContentSecurityPolicy is the page policy for the decrypt-and-sign UI.
// Remote script and connect sources are forbidden so a CDN cannot see the
// PRF-unlocked PhoneRoutineBIP340 software key.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; worker-src 'none'"

// Handler is the public POC HTTP API. It never proxies /v1/onchain-tx.
// Demo routes are absent unless NewHandler is given a non-nil Demo.
func Handler(svc *Service, webDir string) http.Handler {
	return NewHandler(svc, webDir, nil)
}

// AuthorizerHandler is the protected software-box surface. It deliberately
// has no static file handler, demo controller, or raw signing route.
func AuthorizerHandler(svc *Service) http.Handler {
	origin := serviceOrigin(svc)
	mux := http.NewServeMux()
	attachCoreRoutes(mux, svc, origin)
	inner := withCORS(mux, origin)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods, known := authorizerRouteMethods[r.URL.Path]
		if !known {
			http.NotFound(w, r)
			return
		}
		if _, allowed := methods[r.Method]; !allowed {
			w.Header().Set("Allow", strings.Join(sortedMethods(methods), ", "))
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		inner.ServeHTTP(w, r)
	})
}

var authorizerRouteMethods = map[string]map[string]struct{}{
	"/health":       {http.MethodGet: {}},
	"/v1/status":    {http.MethodGet: {}, http.MethodOptions: {}},
	"/v1/register":  {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/preflight": {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/draft":     {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/bind":      {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/authorize": {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/publish":   {http.MethodPost: {}, http.MethodOptions: {}},
	"/v1/tx":        {http.MethodGet: {}, http.MethodOptions: {}},
}

func sortedMethods(methods map[string]struct{}) []string {
	out := make([]string, 0, len(methods))
	for method := range methods {
		out = append(out, method)
	}
	sort.Strings(out)
	return out
}

// NewHandler builds the public API. A nil demo is fail-closed: /v1/demo/*
// is 404 and never reaches Bitcoin RPC.
func NewHandler(svc *Service, webDir string, demo *Demo) http.Handler {
	origin := serviceOrigin(svc)
	mux := http.NewServeMux()
	attachCoreRoutes(mux, svc, origin)
	if demo != nil {
		demo.attach(mux, origin)
	} else {
		mux.HandleFunc("/v1/demo/", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "404 page not found", http.StatusNotFound)
		})
	}
	if webDir != "" {
		mux.Handle("/", http.FileServer(http.Dir(webDir)))
	}
	return withCORS(mux, origin)
}

func serviceOrigin(svc *Service) string {
	if svc == nil {
		return fixture.Origin
	}
	return svc.runtimeConfig().ClientOrigin
}

func attachCoreRoutes(mux *http.ServeMux, svc *Service, origin string) {
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		st, err := svc.Status(r.Context())
		writeJSON(w, st, err)
	})
	mux.HandleFunc("POST /v1/register", func(w http.ResponseWriter, r *http.Request) {
		var req RegisterRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		err := svc.RegisterWithBootstrap(req, r.Header.Get(EnrollmentTokenHeader))
		writeJSON(w, map[string]any{"ok": err == nil}, err)
	})
	mux.HandleFunc("POST /v1/preflight", func(w http.ResponseWriter, r *http.Request) {
		var req PreflightRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		resp, err := svc.PreflightContext(r.Context(), req.PSBT)
		writeJSON(w, resp, err)
	})
	mux.HandleFunc("POST /v1/draft", func(w http.ResponseWriter, r *http.Request) {
		var req DraftRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		psbt, err := svc.DraftContext(r.Context(), req)
		writeJSON(w, map[string]any{"psbt": psbt}, err)
	})
	mux.HandleFunc("POST /v1/bind", func(w http.ResponseWriter, r *http.Request) {
		var req BindRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		psbt, err := svc.BindContext(r.Context(), req)
		writeJSON(w, map[string]any{"psbt": psbt}, err)
	})
	mux.HandleFunc("POST /v1/authorize", func(w http.ResponseWriter, r *http.Request) {
		var req AuthorizeRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		signed, replay, err := svc.Authorize(r.Context(), req)
		writeJSON(w, map[string]any{"signedPsbt": signed, "replay": replay}, err)
	})
	mux.HandleFunc("POST /v1/publish", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Challenge string `json:"challenge"`
		}
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		opCtx, cancel := context.WithTimeout(r.Context(), publishOperationTimeout)
		defer cancel()
		out, err := svc.Publish(opCtx, req.Challenge)
		writeJSON(w, out, err)
	})
	mux.HandleFunc("GET /v1/tx", func(w http.ResponseWriter, r *http.Request) {
		opCtx, cancel := context.WithTimeout(r.Context(), publishOperationTimeout)
		defer cancel()
		out, err := svc.PublicationStatus(opCtx, r.URL.Query().Get("challenge"))
		writeJSON(w, out, err)
	})
}

type mutationError struct {
	status int
	msg    string
}

func (e *mutationError) Error() string { return e.msg }

func decodeMutation(r *http.Request, dst any, expectedOrigin string) error {
	ct := r.Header.Get("Content-Type")
	if ct != "application/json" && !strings.HasPrefix(ct, "application/json;") {
		return &mutationError{http.StatusUnsupportedMediaType, "content-type"}
	}
	if expectedOrigin == "" || r.Header.Get("Origin") != expectedOrigin {
		return &mutationError{http.StatusForbidden, "origin"}
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("multiple json values")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("multiple json values")
	}
	return nil
}

func writeMutationError(w http.ResponseWriter, err error) {
	var me *mutationError
	if errors.As(err, &me) {
		http.Error(w, me.msg, me.status)
		return
	}
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

func writeJSON(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrVerificationBusy) {
			status = http.StatusTooManyRequests
			w.Header().Set("Retry-After", "1")
		} else {
			log.Printf("provider error: %s", redact(err.Error()))
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

func withCORS(next http.Handler, origin string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", ContentSecurityPolicy)
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, "+EnrollmentTokenHeader)
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Never serve a generic emulator signing path.
		if strings.HasPrefix(r.URL.Path, "/v1/onchain-tx") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
