#!/usr/bin/env bun
// Run a command in its own process group and bound the entire descendant tree.
// This prevents a timed-out Compose child from racing project cleanup.

import { spawn } from "node:child_process";

const seconds = Number(process.argv[2]);
const command = process.argv.slice(3);
if (!Number.isFinite(seconds) || seconds <= 0 || command.length === 0) {
  console.error("usage: run-bounded.mjs SECONDS COMMAND [ARG ...]");
  process.exit(2);
}

const child = spawn(command[0], command.slice(1), {
  detached: process.platform !== "win32",
  env: process.env,
  stdio: "inherit",
});

const completed = new Promise((resolve) => {
  child.once("close", (code, signal) => resolve({ code, signal }));
  child.once("error", (error) => resolve({ error }));
});

let signalResolve;
const interrupted = new Promise((resolve) => { signalResolve = resolve; });
const signals = new Map([["SIGHUP", 129], ["SIGINT", 130], ["SIGTERM", 143]]);
for (const [signal, code] of signals) {
  process.once(signal, () => signalResolve({ signal, code }));
}

let timeout;
const expired = new Promise((resolve) => {
  timeout = setTimeout(() => resolve({ timeout: true, code: 124 }), seconds * 1_000);
});

const outcome = await Promise.race([
  completed.then((result) => ({ completed: result })),
  interrupted,
  expired,
]);
clearTimeout(timeout);

if (outcome.completed) {
  const result = outcome.completed;
  if (result.error) {
    console.error(`${command[0]}: ${result.error.message}`);
    process.exit(127);
  }
  process.exit(result.code ?? 1);
}

terminateGroup(outcome.signal || "SIGTERM");
if (!await waitForGroupExit(5_000)) {
  // Kill the group even if its leader exited: a grandchild may have ignored TERM.
  terminateGroup("SIGKILL");
  if (!await waitForGroupExit(1_000)) {
    console.error(`failed to terminate command process group: ${command.join(" ")}`);
    process.exit(125);
  }
}

if (outcome.timeout) {
  console.error(`command timed out after ${seconds}s: ${command.join(" ")}`);
}
process.exit(outcome.code);

function terminateGroup(signal) {
  if (!Number.isInteger(child.pid)) return;
  try {
    if (process.platform === "win32") child.kill(signal);
    else process.kill(-child.pid, signal);
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
}

function groupIsAlive() {
  if (!Number.isInteger(child.pid)) return false;
  if (process.platform === "win32") return child.exitCode === null;
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    throw error;
  }
}

async function waitForGroupExit(milliseconds) {
  const deadline = Date.now() + milliseconds;
  while (Date.now() < deadline) {
    if (!groupIsAlive()) return true;
    await Bun.sleep(50);
  }
  return !groupIsAlive();
}
