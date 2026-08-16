FROM golang:1.26.6 AS builder

WORKDIR /src
COPY go.mod go.sum ./
COPY api-spec/go.mod api-spec/go.sum ./api-spec/
COPY pkg/arkade/go.mod pkg/arkade/go.sum ./pkg/arkade/
COPY pkg/client/go.mod pkg/client/go.sum ./pkg/client/
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /out/vault-provider ./poc/2fa-vault/cmd/provider

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
RUN mkdir -p /app/data
COPY --from=builder /out/vault-provider /usr/local/bin/vault-provider
COPY poc/2fa-vault/web /app/web
EXPOSE 8787
# REGTEST demo image: cmd/provider. ExternalOwnerWallet and RecoveryKey are
# public keys only. Browser enrollment supplies PhoneRoutineBIP340; SQLite
# lives on /app/data. Mutinynet uses Dockerfile.mutinynet/cmd/authorizer.
ENTRYPOINT ["vault-provider", "-addr", "0.0.0.0:8787", "-emulator", "emulator:7073", "-web", "/app/web", "-db", "/app/data/vault.sqlite"]
