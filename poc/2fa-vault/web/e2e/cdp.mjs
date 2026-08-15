import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export async function launchChrome(url) {
  const profile = mkdtempSync(join(tmpdir(), "arkade-chrome-"));
  const child = Bun.spawn([
    findChrome(),
    "--headless=new",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--no-first-run",
    "--no-default-browser-check",
    "--remote-debugging-port=0",
    "--remote-allow-origins=*",
    `--user-data-dir=${profile}`,
    url,
  ], { stdout: "ignore", stderr: "ignore" });
  let childExited = false;
  child.exited.then(() => { childExited = true; });
  try {
    const startupDeadline = Date.now() + 20_000;
    const port = await devtoolsPort(profile, () => childExited, startupDeadline);
    const page = await pageTarget(port, url, () => childExited, startupDeadline);
    const cdp = await CDP.connect(page.webSocketDebuggerUrl);
    return {
      cdp,
      async close() {
        cdp.close();
        child.kill();
        await Promise.race([child.exited, Bun.sleep(2_000)]);
        rmSync(profile, { recursive: true, force: true });
      },
    };
  } catch (error) {
    child.kill();
    await Promise.race([child.exited, Bun.sleep(2_000)]);
    rmSync(profile, { recursive: true, force: true });
    throw error;
  }
}

export async function addPRFAuthenticator(cdp) {
  await cdp.send("WebAuthn.enable");
  return cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      hasPrf: true,
    },
  });
}

export async function evaluate(cdp, fn, ...args) {
  const expression = `(${fn.toString()})(${args.map((arg) => JSON.stringify(arg)).join(",")})`;
  const result = await cdp.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (result.exceptionDetails) {
    throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
  }
  return result.result?.value;
}

function findChrome() {
  const candidates = [
    process.env.CHROME_BIN,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ].filter(Boolean);
  const found = candidates.find(existsSync);
  if (!found) throw new Error("Chrome not found; set CHROME_BIN to a Chrome/Chromium executable");
  return found;
}

async function devtoolsPort(profile, exited, deadline) {
  const active = join(profile, "DevToolsActivePort");
  while (Date.now() < deadline) {
    if (existsSync(active)) {
      const port = Number(readFileSync(active, "utf8").split(/\r?\n/, 1)[0]);
      if (Number.isInteger(port) && port > 0) return port;
    }
    if (exited()) throw new Error("Chrome exited before opening DevTools");
    await Bun.sleep(50);
  }
  throw new Error("timed out waiting for Chrome DevTools");
}

async function pageTarget(port, url, exited, deadline) {
  while (Date.now() < deadline) {
    if (exited()) throw new Error("Chrome exited before creating a page target");
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`, {
        signal: AbortSignal.timeout(500),
      });
      const targets = await response.json();
      const target = targets.find((item) => item.type === "page" && item.url.startsWith(url));
      if (target?.webSocketDebuggerUrl) return target;
    } catch {
      // Chrome can publish the port before the target list is ready.
    }
    await Bun.sleep(50);
  }
  throw new Error("timed out waiting for the localhost page target");
}

class CDP {
  static async connect(url) {
    const ws = new WebSocket(url);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        ws.close();
        reject(new Error("timed out connecting to DevTools WebSocket"));
      }, 10_000);
      ws.addEventListener("open", () => {
        clearTimeout(timer);
        resolve();
      }, { once: true });
      ws.addEventListener("error", () => {
        clearTimeout(timer);
        reject(new Error("DevTools WebSocket failed"));
      }, { once: true });
    });
    return new CDP(ws);
  }

  constructor(ws) {
    this.ws = ws;
    this.nextID = 1;
    this.pending = new Map();
    this.listeners = new Map();
    ws.addEventListener("message", (event) => {
      const message = JSON.parse(String(event.data));
      if (message.id) {
        const pending = this.pending.get(message.id);
        if (!pending) return;
        this.pending.delete(message.id);
        if (message.error) pending.reject(new Error(`${message.error.message} (${message.error.code})`));
        else pending.resolve(message.result);
        return;
      }
      for (const listener of this.listeners.get(message.method) || []) listener(message.params);
    });
    ws.addEventListener("close", () => {
      for (const pending of this.pending.values()) pending.reject(new Error("DevTools WebSocket closed"));
      this.pending.clear();
    });
  }

  send(method, params = {}) {
    const id = this.nextID++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  on(method, listener) {
    const listeners = this.listeners.get(method) || [];
    listeners.push(listener);
    this.listeners.set(method, listeners);
    return () => this.listeners.set(method, listeners.filter((item) => item !== listener));
  }

  close() {
    this.ws.close();
  }
}
