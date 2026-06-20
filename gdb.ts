// MIT License
//
// Copyright (c) 2026 Daniel Balster
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import { tool, type Plugin, type PluginInput } from "@kilocode/plugin";
import { spawn, type ChildProcess } from "node:child_process";
import { writeFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { Buffer } from "node:buffer";

// ─── State ───────────────────────────────────────────────────────────────────

const STATE_DIR = "/tmp/kilo-gdb";
const STATE_FILE = join(STATE_DIR, "state.json");

interface GdbState {
  binary?: string;
  args?: string;
  cwd?: string;
  status: "not_started" | "stopped" | "running" | "paused" | "exited" | "crashed" | "signal";
  breakpoints: BpInfo[];
  threads: ThreadInfo[];
  currentThreadId?: number;
  currentFrameLevel?: number;
  varObjs: VarObjInfo[];
  lastSignal?: string;
  lastStopReason?: string;
  lastStopFrame?: Record<string, unknown>;
  token: number;
}

interface BpInfo {
  number: number;
  type: string;
  enabled: boolean;
  func?: string;
  file?: string;
  fullname?: string;
  line?: number;
  addr?: string;
  pending?: boolean;
  times: number;
  condition?: string;
  ignore?: number;
  what?: string;
  at?: string;
}

interface ThreadInfo {
  id: number;
  targetId: string;
  state: string;
  frame?: {
    level: number;
    func: string;
    file?: string;
    fullname?: string;
    line?: number;
    addr?: string;
    from?: string;
  };
}

interface VarObjInfo {
  name: string;
  expression: string;
  type?: string;
  value?: string;
  numChildren: number;
  hasMore?: boolean;
}

interface MiResponse {
  token: number;
  command: string;
  raw: string;
  resultClass: string;
  resultData: Record<string, MiValue>;
  records: MiRecord[];
  lines: string[];
}

type MiRecord =
  | { type: "result"; token?: number; recordClass?: string; data?: Record<string, MiValue> }
  | { type: "exec"; token?: number; recordClass?: string; data?: Record<string, MiValue> }
  | { type: "notify"; token?: number; recordClass?: string; data?: Record<string, MiValue> }
  | { type: "console" | "target" | "log"; text?: string }
  | { type: "prompt" };

interface MiValueMap { [key: string]: MiValue; }
type MiValue = string | MiValueMap | MiValue[];
type MiTuple = MiValueMap;

function saveState(s: GdbState): void {
  if (!existsSync(STATE_DIR)) mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(STATE_FILE, JSON.stringify(s, null, 2));
}

function loadState(): GdbState {
  try {
    if (existsSync(STATE_FILE)) return JSON.parse(readFileSync(STATE_FILE, "utf-8"));
  } catch { /* ignore */ }
  return {
    status: "not_started",
    breakpoints: [],
    threads: [],
    varObjs: [],
    token: 0,
  };
}

function freshState(): GdbState {
  return {
    status: "stopped",
    breakpoints: [],
    threads: [],
    varObjs: [],
    token: 0,
  };
}

// ─── MI Parser ───────────────────────────────────────────────────────────────

type MiToken =
  | { type: "string"; value: string }
  | { type: "lbrace" }
  | { type: "rbrace" }
  | { type: "lbracket" }
  | { type: "rbracket" }
  | { type: "comma" }
  | { type: "equals" }
  | { type: "nl" }
  | { type: "eof" };

const TOKEN_CHAR_MAP: Record<string, MiToken["type"]> = {
  "{": "lbrace", "}": "rbrace",
  "[": "lbracket", "]": "rbracket",
  ",": "comma", "=": "equals",
};

function miTokenize(input: string): MiToken[] {
  const tokens: MiToken[] = [];
  let i = 0;
  while (i < input.length) {
    const ch = input[i];
    if (ch in TOKEN_CHAR_MAP) {
      tokens.push({ type: TOKEN_CHAR_MAP[ch] } as MiToken);
      i++;
    } else if (ch === '"') {
      i++;
      let val = "";
      while (i < input.length && input[i] !== '"') {
        if (input[i] === "\\" && i + 1 < input.length) {
          const esc = input[i + 1];
          if (esc === "n") val += "\n";
          else if (esc === "t") val += "\t";
          else if (esc === "r") val += "\r";
          else if (esc === '"') val += '"';
          else if (esc === "\\") val += "\\";
          else val += esc;
          i += 2;
        } else {
          val += input[i];
          i++;
        }
      }
      if (i < input.length) i++;
      tokens.push({ type: "string", value: val });
    } else if (ch === "\n") {
      tokens.push({ type: "nl" });
      i++;
    } else if (ch === " " || ch === "\t" || ch === "\r") {
      i++;
    } else {
      let val = "";
      while (i < input.length && !"{}[]=, \"\t\n\r".includes(input[i])) {
        val += input[i];
        i++;
      }
      tokens.push({ type: "string", value: val });
    }
  }
  tokens.push({ type: "eof" });
  return tokens;
}

function miParseValue(tokens: MiToken[], idx: { i: number }): MiValue {
  const t = tokens[idx.i];
  idx.i++;
  if (!t || t.type === "eof") return "";
  if (t.type === "string") return t.value;
  if (t.type === "lbrace") {
    const obj: MiValueMap = {};
    while (idx.i < tokens.length) {
      const tok = tokens[idx.i];
      if (tok.type === "rbrace") { idx.i++; break; }
      if (tok.type === "string") {
        const key = tok.value;
        idx.i++;
        const eq = tokens[idx.i];
        if (eq && eq.type === "equals") {
          idx.i++;
          obj[key] = miParseValue(tokens, idx);
          const comma = tokens[idx.i];
          if (comma && comma.type === "comma") idx.i++;
          else if (comma && comma.type === "rbrace") continue;
          else continue;
        } else continue;
      } else { idx.i++; }
    }
    return obj;
  }
  if (t.type === "lbracket") {
    const arr: MiValue[] = [];
    while (idx.i < tokens.length) {
      const tok = tokens[idx.i];
      if (tok.type === "rbracket") { idx.i++; break; }
      if (tok.type === "lbrace") {
        arr.push(miParseValue(tokens, idx));
        const comma = tokens[idx.i];
        if (comma && comma.type === "comma") idx.i++;
      } else if (tok.type === "lbracket") {
        arr.push(miParseValue(tokens, idx));
        const comma = tokens[idx.i];
        if (comma && comma.type === "comma") idx.i++;
      } else if (tok.type === "string") {
        const label = tok.value;
        idx.i++;
        const eq = tokens[idx.i];
        if (eq && eq.type === "equals") {
          idx.i++;
          arr.push(miParseValue(tokens, idx));
        } else {
          arr.push(label);
        }
        const comma = tokens[idx.i];
        if (comma && comma.type === "comma") idx.i++;
      } else { idx.i++; }
    }
    return arr;
  }
  return "";
}

function miParseEntry(input: string): Record<string, MiValue> {
  const tokens = miTokenize(input.trim());
  const obj: Record<string, MiValue> = {};
  const idx = { i: 0 };
  while (idx.i < tokens.length) {
    const tok = tokens[idx.i];
    if (tok.type === "eof") break;
    if (tok.type === "string") {
      const key = tok.value;
      idx.i++;
      const eq = tokens[idx.i];
      if (eq && eq.type === "equals") {
        idx.i++;
        obj[key] = miParseValue(tokens, idx);
        const comma = tokens[idx.i];
        if (comma && comma.type === "comma") idx.i++;
        else if (comma && comma.type === "eof") break;
      } else { idx.i++; }
    } else { idx.i++; }
  }
  return obj;
}

function miFlattenValue(v: MiValue, indent = ""): string {
  if (typeof v === "string") return v;
  if (Array.isArray(v)) {
    if (v.length === 0) return "[]";
    return v.map((e, i) => {
      if (typeof e === "string") return `[${i}]: ${e}`;
      if (Array.isArray(e)) return `[${i}]: ${miFlattenValue(e, indent + "  ")}`;
      return `[${i}]: ${miFlattenTuple(e as MiTuple, indent + "  ")}`;
    }).join("\n" + indent);
  }
  return miFlattenTuple(v as MiTuple, indent);
}

function miFlattenTuple(t: MiTuple, indent = ""): string {
  return Object.entries(t).map(([k, v]) => {
    if (typeof v === "string") return `${indent}${k}: ${v}`;
    if (Array.isArray(v)) return `${indent}${k}: [${v.length} items]`;
    return `${indent}${k}: {${Object.keys(v as MiTuple).length} fields}`;
  }).join("\n");
}

// ─── GDB Manager ─────────────────────────────────────────────────────────────

type PendingEntry = {
  resolve: (v: MiResponse) => void;
  reject: (e: Error) => void;
  token: number;
  command: string;
  timer: ReturnType<typeof setTimeout>;
};

class GdbManager {
  private proc: ChildProcess | null = null;
  private state: GdbState;
  private pending: PendingEntry | null = null;
  private cmdQueue: Array<{
    cmd: string;
    needsStopped: boolean;
    timeout: number;
    resolve: (v: MiResponse) => void;
    reject: (e: Error) => void;
  }> = [];
  private cmdBusy = false;
  private lines: string[] = [];
  private records: MiRecord[] = [];
  private promptSeen = false;

  constructor() {
    this.state = loadState();
  }

  getState(): Readonly<GdbState> {
    return this.state;
  }

  isRunning(): boolean {
    return this.proc !== null && this.proc.exitCode === null;
  }

  async start(binary?: string, gdbArgs?: string, cwd?: string): Promise<string> {
    this.forceKill();

    this.state = freshState();
    this.state.binary = binary || this.state.binary;
    this.state.cwd = cwd || this.state.cwd;
    this.records = [];
    this.lines = [];
    this.promptSeen = false;
    this.pending = null;
    this.cmdQueue = [];
    this.cmdBusy = true;

    const args: string[] = ["--interpreter=mi3", "--quiet"];
    if (gdbArgs) args.push(...gdbArgs.split(/\s+/));
    if (binary) args.push(binary);

    this.proc = spawn("gdb", args, {
      cwd: cwd || undefined,
      stdio: ["pipe", "pipe", "pipe"],
    });

    const rl = createInterface({ input: this.proc.stdout! });
    const errChunks: string[] = [];

    let stderrSize = 0;
    const MAX_STDERR = 102400;
    this.proc.stderr!.on("data", (chunk: Buffer) => {
      const s = chunk.toString();
      stderrSize += s.length;
      if (stderrSize <= MAX_STDERR) errChunks.push(s);
    });

    rl.on("line", (line: string) => this.handleLine(line));

    this.proc.on("exit", (code: number | null) => {
      if (!this.pending) return;
      if (this.pending.timer) clearTimeout(this.pending.timer);
      this.pending.reject(new Error(`GDB exited with code ${code}`));
      this.pending = null;
      this.proc = null;
      this.state.status = "exited";
      saveState(this.state);
    });

    await this.waitForPrompt(10000);
    await this.rawCommand("-gdb-set pagination off");
    await this.rawCommand("-gdb-set print pretty on");
    await this.rawCommand("-gdb-set print thread-events on");

    const out = errChunks.join("");
    const info = [
      this.state.binary ? `GDB loaded: ${this.state.binary}` : "GDB started (no binary)",
      out ? `stderr: ${out}` : "",
    ].filter(Boolean).join("\n");

    saveState(this.state);
    this.cmdBusy = false;
    return info;
  }

  forceKill(): void {
    if (this.pending) {
      clearTimeout(this.pending.timer);
      this.pending = null;
    }
    if (this.proc) {
      try { this.proc.stdin?.write("-gdb-exit\n"); } catch { /* ignore */ }
      try { this.proc.kill("SIGKILL"); } catch { /* ignore */ }
      this.proc = null;
    }
    this.state.status = "not_started";
    this.state.threads = [];
    this.state.varObjs = [];
    this.state.lastStopReason = undefined;
    this.state.lastSignal = undefined;
    this.lines = [];
    this.records = [];
    this.promptSeen = false;
    this.pending = null;
    this.cmdBusy = false;
    for (const q of this.cmdQueue) {
      q.resolve({
        token: this.state.token, command: q.cmd, raw: "GDB killed",
        resultClass: "error", resultData: { msg: "GDB process was killed" },
        records: [], lines: [],
      });
    }
    this.cmdQueue = [];
    saveState(this.state);
  }

  stop(): string {
    if (this.proc) {
      try { this.proc.stdin?.write("-gdb-exit\n"); } catch { /* ignore */ }
      try { this.proc.kill("SIGKILL"); } catch { /* ignore */ }
      this.proc = null;
    }
    this.state.status = "not_started";
    this.state.threads = [];
    this.state.varObjs = [];
    this.state.lastStopReason = undefined;
    this.state.lastSignal = undefined;
    this.pending = null;
    saveState(this.state);
    return "GDB terminated";
  }

  ensureAlive(): void {
    if (!this.proc) throw new Error("GDB is not running. Call gdbInit first.");
    if (this.proc.exitCode !== null) {
      this.state.status = "exited";
      saveState(this.state);
      throw new Error(`GDB process exited with code ${this.proc.exitCode}. Call gdbInit to restart.`);
    }
  }

  requireStopped(): void {
    if (this.state.status === "running") {
      throw new Error("Program is currently running. Interrupt it (gdbInterrupt) before using this command.");
    }
    if (this.state.status === "exited" || this.state.status === "not_started") {
      throw new Error(`Target program is ${this.state.status}. Start it with gdbRun first.`);
    }
  }

  drainStaleResponse(): void {
    if (this.pending) {
      clearTimeout(this.pending.timer);
      this.pending = null;
    }
  }

  interrupt(): Promise<MiResponse> {
    if (!this.proc) throw new Error("GDB not running");
    this.drainStaleResponse();
    this.lines = [];
    this.records = [];
    this.promptSeen = false;

    return new Promise<MiResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending === p) {
          this.pending = null;
          reject(new Error("GDB interrupt timed out."));
        }
      }, 10000);

      const p = { resolve, reject, token: -1, command: "interrupt", timer };
      this.pending = p;
      for (const q of this.cmdQueue) {
        q.resolve({
          token: this.state.token, command: q.cmd, raw: "Interrupted by gdbInterrupt",
          resultClass: "error", resultData: { msg: "Interrupted" },
          records: [], lines: [],
        });
      }
      this.cmdQueue = [];
      this.cmdBusy = false;
      this.proc!.kill("SIGINT");
    });
  }

  async command(cmd: string, needsStopped = false, timeout = 30000): Promise<MiResponse> {
    try {
      this.ensureAlive();
      if (needsStopped) this.requireStopped();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return { token: this.state.token, command: cmd, raw: msg, resultClass: "error", resultData: { msg }, records: [], lines: [] };
    }

    return new Promise<MiResponse>((resolve, reject) => {
      this.cmdQueue.push({ cmd, needsStopped, timeout, resolve, reject });
      this.processQueue();
    });
  }

  private async processQueue(): Promise<void> {
    if (this.cmdBusy || this.cmdQueue.length === 0) return;
    this.cmdBusy = true;
    const item = this.cmdQueue.shift()!;
    try {
      this.drainStaleResponse();
      this.promptSeen = false;
      const result = await this.rawCommand(item.cmd, item.timeout);
      item.resolve(result);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      item.resolve({ token: this.state.token, command: item.cmd, raw: msg, resultClass: "error", resultData: { msg }, records: [], lines: [] });
    } finally {
      this.cmdBusy = false;
      this.processQueue();
    }
  }

  private async rawCommand(cmd: string, timeoutMs = 30000): Promise<MiResponse> {
    if (!this.proc || !this.proc.stdin) throw new Error("GDB not running.");
    const token = ++this.state.token;
    const fullCmd = `${token}${cmd}\n`;
    this.lines = [];
    this.records = [];
    this.promptSeen = false;

    return new Promise<MiResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending === p) {
          this.pending = null;
          const hint = this.state.status === "running"
            ? " (target program is still running — interrupt it first)"
            : "";
          reject(new Error(`GDB command timed out after ${timeoutMs}ms: ${cmd}${hint}`));
        }
      }, timeoutMs);

      const p = { resolve, reject, token, command: cmd, timer };
      this.pending = p;
      this.proc!.stdin!.write(fullCmd);
    });
  }

  private async waitForPrompt(timeout = 30000): Promise<void> {
    const start = Date.now();
    while (!this.promptSeen && this.proc?.exitCode === null) {
      if (Date.now() - start > timeout) throw new Error("Timeout waiting for GDB prompt");
      await new Promise((r) => setTimeout(r, 10));
    }
  }

  private handleLine(line: string): void {
    this.lines.push(line);

    if (line.startsWith("(gdb)")) {
      this.promptSeen = true;
      this.records.push({ type: "prompt" });

      if (this.pending) {
        clearTimeout(this.pending.timer);
        const p = this.pending;
        this.pending = null;

        const resultClass = this.findResultClass();
        const resultData = this.findResultData();
        const resp: MiResponse = {
          token: p.token,
          command: p.command,
          raw: this.lines.join("\n"),
          resultClass,
          resultData,
          records: [...this.records],
          lines: [...this.lines],
        };

        this.updateStateFromRecords(resp);
        p.resolve(resp);
      }
      return;
    }

    const resultMatch = line.match(/^(\d+)\^(done|running|error|connected|exit)((?:,.+)*)$/);
    if (resultMatch) {
      const token = parseInt(resultMatch[1]);
      const cls = resultMatch[2];
      const rest = resultMatch[3];
      const data = rest ? miParseEntry(rest.startsWith(",") ? rest.slice(1) : rest) : {};
      this.records.push({ type: "result", token, recordClass: cls, data });
      return;
    }

    const execMatch = line.match(/^\*(\w+)((?:,.+)*)$/);
    if (execMatch) {
      const cls = execMatch[1];
      const rest = execMatch[2];
      const data = rest ? miParseEntry(rest.startsWith(",") ? rest.slice(1) : rest) : {};
      this.records.push({ type: "exec", recordClass: cls, data });
      if (cls === "stopped") {
        this.state.lastStopReason = (data.reason as string) || "";
        this.state.lastSignal = (data.signal as string) || (data.signalName as string) || "";
        this.state.lastStopFrame = (data.frame as MiValueMap) || {};
        if (this.state.lastStopReason === "exited" || this.state.lastStopReason === "exited-signalled") {
          this.state.status = "exited";
        } else if (this.state.lastStopReason === "signal-received") {
          this.state.status = "signal";
        } else {
          this.state.status = "paused";
        }
        if (data["thread-id"]) {
          this.state.currentThreadId = parseInt(data["thread-id"] as string);
        }
        this.state.currentFrameLevel = 0;
        saveState(this.state);
      } else if (cls === "running") {
        this.state.status = "running";
        saveState(this.state);
      }
      return;
    }

    const notifyMatch = line.match(/^=(\w+)((?:,.+)*)$/);
    if (notifyMatch) {
      const cls = notifyMatch[1];
      const rest = notifyMatch[2];
      const data = rest ? miParseEntry(rest.startsWith(",") ? rest.slice(1) : rest) : {};
      this.records.push({ type: "notify", recordClass: cls, data });
      if (cls === "breakpoint-modified" || cls === "breakpoint-created" || cls === "breakpoint-deleted") {
        this.syncBreakpoints();
      }
      return;
    }

    const streamMatch = line.match(/^([~@&])"(.*)"\s*$/s);
    if (streamMatch) {
      const typeMap: Record<string, "console" | "target" | "log"> = { "~": "console", "@": "target", "&": "log" };
      const text = streamMatch[2].replace(/\\(.)/g, (_, c) => c === "n" ? "\n" : c === "t" ? "\t" : c === '"' ? '"' : c === "\\" ? "\\" : c);
      this.records.push({ type: typeMap[streamMatch[1]], text });
      return;
    }
  }

  private findResultClass(): string {
    for (const r of this.records) {
      if (r.type === "result" && r.token === this.state.token) return r.recordClass || "unknown";
    }
    return "unknown";
  }

  private findResultData(): Record<string, MiValue> {
    for (const r of this.records) {
      if (r.type === "result" && r.token === this.state.token) return r.data || {};
    }
    return {};
  }

  private updateStateFromRecords(resp: MiResponse): void {
    for (const r of resp.records) {
      if (r.type === "exec" && r.recordClass === "stopped") {
        const d = r.data || {};
        this.state.lastStopReason = (d.reason as string) || "";
        this.state.lastSignal = (d.signal as string) || (d.signalName as string) || "";
        this.state.lastStopFrame = (d.frame as MiTuple) || {};

        if (this.state.lastStopReason === "exited") {
          this.state.status = "exited";
        } else if (this.state.lastStopReason === "signal-received") {
          this.state.status = "signal";
        } else if (
          this.state.lastStopReason?.includes("breakpoint") ||
          this.state.lastStopReason === "function-finished" ||
          this.state.lastStopReason === "end-stepping-range" ||
          this.state.lastStopReason === "watchpoint"
        ) {
          this.state.status = "paused";
        } else {
          this.state.status = "crashed";
        }

        if (d["thread-id"]) {
          this.state.currentThreadId = parseInt(d["thread-id"] as string);
        }
        this.state.currentFrameLevel = 0;
      }

      if (r.type === "exec" && r.recordClass === "running") {
        this.state.status = "running";
      }

      if (r.type === "result" && r.token === this.state.token) {
        if (r.recordClass === "running") this.state.status = "running";
        if (r.recordClass === "error") {
          const msg = (r.data?.msg as string) || "";
          if (msg.includes("No such process") || msg.includes(" exited")) {
            this.state.status = "exited";
          }
        }
      }
    }
    saveState(this.state);
  }

  addVarObj(info: VarObjInfo): void {
    this.state.varObjs.push(info);
    saveState(this.state);
  }

  removeVarObj(name: string): void {
    this.state.varObjs = this.state.varObjs.filter((v) => v.name !== name);
    saveState(this.state);
  }

  setCurrentThread(id: number): void {
    this.state.currentThreadId = id;
    this.state.currentFrameLevel = 0;
    saveState(this.state);
  }

  setCurrentFrame(level: number): void {
    this.state.currentFrameLevel = level;
    saveState(this.state);
  }

  setArgs(args: string): void {
    this.state.args = args;
    saveState(this.state);
  }

  async syncBreakpoints(): Promise<void> {
    try {
      const r = await this.command("-break-list", false);
      if (r.resultClass === "done" && r.resultData?.BreakpointTable) {
        const table = r.resultData.BreakpointTable as MiTuple;
        const body = table.body as MiValue[];
        if (Array.isArray(body)) {
          this.state.breakpoints = body
            .filter((b): b is MiValueMap => typeof b === "object" && !Array.isArray(b) && b !== null)
            .map((e: MiValueMap) => ({
              number: parseInt((e.number as string) || "0"),
              type: (e.type as string) || "",
              enabled: (e.enabled as string) === "y",
              func: e.func as string,
              file: e.file as string,
              fullname: e.fullname as string,
              line: e.line ? parseInt(e.line as string) : undefined,
              addr: e.addr as string,
              pending: (e.pending as string) === "y",
              times: parseInt((e.times as string) || "0"),
              condition: e.cond as string,
              ignore: e.ignore ? parseInt(e.ignore as string) : undefined,
              what: e.what as string,
              at: e.at as string,
            }));
        }
      }
    } catch { /* ignore */ }
    saveState(this.state);
  }

  async syncThreads(): Promise<void> {
    try {
      const r = await this.command("-thread-info", false);
      if (r.resultClass === "done" && r.resultData?.threads) {
        const threads = r.resultData.threads as MiValue[];
        if (Array.isArray(threads)) {
          this.state.threads = threads.map((t: MiValue) => {
            const e = t as MiTuple;
            return {
              id: parseInt((e.id as string) || "0"),
              targetId: (e.targetId as string) || (e["target-id"] as string) || "",
              state: (e.state as string) || "",
              frame: e.frame ? this.parseFrameInfo(e.frame as MiTuple) : undefined,
            };
          });
          if (r.resultData["current-thread-id"]) {
            this.state.currentThreadId = parseInt(r.resultData["current-thread-id"] as string);
          }
        }
      }
    } catch { /* ignore */ }
    saveState(this.state);
  }

  private parseFrameInfo(f: MiTuple): ThreadInfo["frame"] {
    return {
      level: f.level ? parseInt(f.level as string) : 0,
      func: (f.func as string) || "",
      file: f.file as string,
      fullname: f.fullname as string,
      line: f.line ? parseInt(f.line as string) : undefined,
      addr: f.addr as string,
      from: f.from as string,
    };
  }

  private getConsoleOutput(): string {
    return this.records
      .filter((r): r is MiRecord & { type: "console" | "target" | "log"; text: string } =>
        (r.type === "console" || r.type === "target" || r.type === "log") && r.text !== undefined
      )
      .map((r) => r.text)
      .join("");
  }

  formatResponse(resp: MiResponse): string {
    const parts: string[] = [];
    const consoleOut = this.getConsoleOutput();
    if (resp.resultClass === "error") {
      const msg = resp.resultData?.msg as string || "";
      const logMsg = resp.records
        .filter((r): r is MiRecord & { type: "log"; text: string } => r.type === "log" && r.text !== undefined)
        .map((r) => r.text)
        .join("")
        .trim();
      const errText = msg || consoleOut.trim() || logMsg || "unknown error";
      parts.push(`ERROR: ${errText}`);
    }
    if (consoleOut && resp.resultClass !== "error") {
      parts.push(consoleOut);
    }
    return parts.join("\n") || `OK (${resp.resultClass})`;
  }

  formatError(err: unknown): string {
    return `GDB Error: ${err instanceof Error ? err.message : String(err)}`;
  }

  formatStoppedInfo(r: MiResponse, s: GdbState): string[] {
    const out: string[] = [];
    if (s.lastStopReason) out.push(`Reason: ${s.lastStopReason}`);
    if (s.lastSignal) out.push(`Signal: ${s.lastSignal}`);
    if (s.lastStopFrame) {
      const f = s.lastStopFrame as MiTuple;
      const func = f.func as string || "?";
      const file = f.file as string || f.fullname as string || "";
      const line = f.line as string || "";
      if (file) out.push(`At: ${func} (${file}:${line})`);
      else out.push(`At: ${func}`);
    }
    for (const rec of r.records) {
      if (rec.type === "console" && rec.text) out.push(rec.text.replace(/\n$/, ""));
    }
    if (out.length === 0) out.push(`Result: ${r.resultClass}`);
    return out;
  }
}

// ─── Plugin ───────────────────────────────────────────────────────────────────

const manager = new GdbManager();

export default async function gdbPlugin(input: PluginInput): ReturnType<Plugin> {
  const { $, worktree } = input;
  const $cwd = $.nothrow().cwd(worktree);

  return {
    tool: {

      gdbInit: tool({
        description: "Start GDB with a binary executable. Must be called before any other gdb command.",
        args: {
          binary: tool.schema.string().optional().describe("Path to the executable to debug"),
          gdbArgs: tool.schema.string().optional().describe("Extra GDB arguments (e.g. '-q')"),
          cwd: tool.schema.string().optional().describe("Working directory for GDB (default: project root)"),
        },
        async execute(args, ctx) {
          const msg = await manager.start(args.binary, args.gdbArgs, args.cwd);
          return { output: msg };
        },
      }),

      gdbLoad: tool({
        description: "Load a new binary/symbol file into GDB (replaces existing target).",
        args: {
          binary: tool.schema.string().describe("Path to the executable or symbol file"),
          args: tool.schema.string().optional().describe("Program arguments"),
        },
        async execute(args, ctx) {
          const r = await manager.command(`-file-exec-and-symbols ${args.binary}`);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          if (args.args) {
            const r2 = await manager.command(`-exec-arguments ${args.args}`);
            if (r2.resultClass === "error") return { output: `Binary loaded but args error: ${r2.resultData.msg}` };
          }
          return { output: `Loaded: ${args.binary}` };
        },
      }),

      gdbRun: tool({
        description: "Run (or restart) the debugged program from the beginning.",
        args: {},
        async execute(_args, ctx) {
          const r = await manager.command("-exec-run", false);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          if (r.resultClass === "running") return { output: "Program running..." };
          return { output: manager.formatResponse(r) };
        },
      }),

      gdbContinue: tool({
        description: "Continue execution of a paused/stopped program.",
        args: {},
        async execute(_args, ctx) {
          const r = await manager.command("-exec-continue", false);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          return { output: "Continuing..." };
        },
      }),

      gdbInterrupt: tool({
        description: "Interrupt the running program (send SIGINT to GDB).",
        args: {},
        async execute(_args, ctx) {
          try {
            const r = await manager.interrupt();
            const s = manager.getState();
            const reason = s.lastStopReason || "interrupted";
            const lines = manager.formatStoppedInfo(r, s);
            return { output: [`Interrupted (${reason})`, ...lines].join("\n") };
          } catch (e) {
            return { output: manager.formatError(e) };
          }
        },
      }),

      gdbStep: tool({
        description: "Step into the next source line (enter function calls).",
        args: {
          count: tool.schema.number().optional().describe("Number of steps (default: 1)"),
        },
        async execute(args, ctx) {
          const n = args.count ?? 1;
          const r = await manager.command(`-exec-step ${n}`, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          const s = manager.getState();
          const lines = manager.formatStoppedInfo(r, s);
          return { output: lines.join("\n") };
        },
      }),

      gdbNext: tool({
        description: "Step over the next source line (skip function calls).",
        args: {
          count: tool.schema.number().optional().describe("Number of steps (default: 1)"),
        },
        async execute(args, ctx) {
          const n = args.count ?? 1;
          const r = await manager.command(`-exec-next ${n}`, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          const s = manager.getState();
          const lines = manager.formatStoppedInfo(r, s);
          return { output: lines.join("\n") };
        },
      }),

      gdbFinish: tool({
        description: "Step out of the current function (execute until return).",
        args: {},
        async execute(_args, ctx) {
          const r = await manager.command("-exec-finish", true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          const s = manager.getState();
          const lines = manager.formatStoppedInfo(r, s);
          return { output: lines.join("\n") };
        },
      }),

      gdbBreak: tool({
        description: "Set a breakpoint at a location (function, file:line, or address).",
        args: {
          location: tool.schema.string().describe("Breakpoint location (e.g. 'main', 'file.cpp:42', '*0x400000')"),
          condition: tool.schema.string().optional().describe("Breakpoint condition"),
          ignore: tool.schema.number().optional().describe("Ignore count"),
          enabled: tool.schema.boolean().optional().describe("Start enabled (default: true)"),
          thread: tool.schema.number().optional().describe("Thread-specific breakpoint"),
        },
        async execute(args, ctx) {
          let cmd = `-break-insert`;
          if (args.thread) cmd += ` --thread ${args.thread}`;
          if (args.enabled === false) cmd += ` --disabled`;
          cmd += ` ${args.location}`;

          const r = await manager.command(cmd);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };

          await manager.syncBreakpoints();
          const bps = manager.getState().breakpoints;
          const bp = bps[bps.length - 1];
          const info = bp ? `Breakpoint ${bp.number} at ${bp.func || bp.file || args.location} (${bp.fullname || ""}:${bp.line || ""})` : `Breakpoint set at ${args.location}`;

          if (args.condition) {
            if (!bp) return { output: `${info}\nCondition NOT set (no breakpoint number found).` };
            const r2 = await manager.command(`-break-condition ${bp.number} ${args.condition}`);
            if (r2.resultClass === "error") return { output: `${info}\nCondition error: ${r2.resultData.msg}` };
          }
          if (args.ignore && bp) {
            await manager.command(`-break-after ${bp.number} ${args.ignore}`);
          }

          return { output: info, metadata: { breakpoint: bp } };
        },
      }),

      gdbBreakpointList: tool({
        description: "List all breakpoints and watchpoints.",
        args: {},
        async execute(_args, ctx) {
          await manager.syncBreakpoints();
          const bps = manager.getState().breakpoints;
          if (bps.length === 0) return { output: "No breakpoints." };
          const lines = bps.map((bp) => {
            const status = bp.enabled ? "enabled" : "disabled";
            const loc = bp.func ? `${bp.func}()` : bp.file ? `${bp.file}:${bp.line}` : bp.what || bp.at || bp.addr || "?";
            const hits = bp.times > 0 ? ` (hit ${bp.times}x)` : "";
            const cond = bp.condition ? ` if ${bp.condition}` : "";
            const ign = bp.ignore && bp.ignore > 0 ? ` (ignore ${bp.ignore})` : "";
            return `  #${bp.number} ${status}  ${loc}${cond}${ign}${hits}`;
          });
          return { output: `Breakpoints:\n${lines.join("\n")}` };
        },
      }),

      gdbBreakpointDelete: tool({
        description: "Delete one or more breakpoints by number.",
        args: {
          number: tool.schema.string().describe("Breakpoint number or range (e.g. '1', '1-5')"),
        },
        async execute(args, ctx) {
          const r = await manager.command(`-break-delete ${args.number}`);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          await manager.syncBreakpoints();
          return { output: `Deleted breakpoint(s) ${args.number}` };
        },
      }),

      gdbBreakpointEnable: tool({
        description: "Enable a breakpoint by number.",
        args: { number: tool.schema.number().describe("Breakpoint number") },
        async execute(args, ctx) {
          const r = await manager.command(`-break-enable ${args.number}`);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          await manager.syncBreakpoints();
          return { output: `Enabled breakpoint ${args.number}` };
        },
      }),

      gdbBreakpointDisable: tool({
        description: "Disable a breakpoint by number.",
        args: { number: tool.schema.number().describe("Breakpoint number") },
        async execute(args, ctx) {
          const r = await manager.command(`-break-disable ${args.number}`);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          await manager.syncBreakpoints();
          return { output: `Disabled breakpoint ${args.number}` };
        },
      }),

      gdbBreakpointCondition: tool({
        description: "Set or clear a condition on an existing breakpoint.",
        args: {
          number: tool.schema.number().describe("Breakpoint number"),
          condition: tool.schema.string().describe("Condition expression (empty to clear)"),
        },
        async execute(args, ctx) {
          const cond = args.condition || "";
          const r = await manager.command(`-break-condition ${args.number} ${cond}`);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          await manager.syncBreakpoints();
          return { output: `Breakpoint ${args.number} condition: ${cond || "(cleared)"}` };
        },
      }),

      gdbWatch: tool({
        description: "Set a watchpoint on a variable (break when value changes).",
        args: {
          expression: tool.schema.string().describe("Variable expression to watch"),
          type: tool.schema.enum(["write", "read", "access"]).optional().describe("Watch type (default: write)"),
        },
        async execute(args, ctx) {
          const type = args.type || "write";
          const cmdMap: Record<string, string> = { write: "-break-watch", read: "-break-watch -r", access: "-break-watch -a" };
          const miCmd = cmdMap[type] || cmdMap.write;
          const r = await manager.command(`${miCmd} ${args.expression}`, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          await manager.syncBreakpoints();
          return { output: `Watchpoint set on ${args.expression} (${type})` };
        },
      }),

      gdbCatch: tool({
        description: "Set a catchpoint for exceptions, signals, or events.",
        args: {
          event: tool.schema.string().describe("Event to catch (e.g. 'throw', 'catch', 'syscall', 'signal SIGSEGV')"),
        },
        async execute(args, ctx) {
          const r = await manager.command(`-catch-${args.event}`, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          await manager.syncBreakpoints();
          return { output: `Catchpoint set on ${args.event}` };
        },
      }),

      gdbBacktrace: tool({
        description: "Print a backtrace of the current thread (call stack).",
        args: {
          count: tool.schema.number().optional().describe("Number of frames to show (default: all)"),
          full: tool.schema.boolean().optional().describe("Show full frame info including arguments (default: false)"),
        },
        async execute(args, ctx) {
          const count = args.count ?? 0;
          const full = args.full ?? false;
          const cmd = count > 0 ? `-stack-list-frames 0 ${count - 1}` : "-stack-list-frames";
          const r = await manager.command(cmd, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };

          const stackVal = r.resultData?.stack;
          let frames: MiValue[] = [];
          if (Array.isArray(stackVal)) {
            frames = stackVal;
          } else if (typeof stackVal === "object" && stackVal !== null) {
            const st = stackVal as MiValueMap;
            const f = st.frame;
            frames = Array.isArray(f) ? f : [f as MiValueMap];
          }

          if (!Array.isArray(frames) || frames.length === 0) return { output: "Empty call stack" };

          const lines: string[] = [];
          for (let i = 0; i < frames.length; i++) {
            const f = frames[i] as MiTuple;
            const level = f.level as string || String(i);
            const func = f.func as string || "??";
            const file = f.file as string || "";
            const fline = f.line as string || "";
            const from = f.from as string || "";
            const loc = file ? `${file}:${fline}` : from || "??";
            lines.push(`  #${level}  ${func} at ${loc}`);

            if (full) {
              try {
                const vr = await manager.command(`-stack-list-variables --thread ${manager.getState().currentThreadId || 1} --frame ${level} --simple-values`, true);
                if (vr.resultClass === "done" && vr.resultData?.variables) {
                  const vars = vr.resultData.variables as MiValue[];
                  if (Array.isArray(vars)) {
                    for (const v of vars) {
                      const ve = v as MiTuple;
                      lines.push(`        ${ve.name as string} = ${(ve.value as string) || (ve.type as string) || "?"}`);
                    }
                  }
                }
              } catch { /* skip */ }
            }
          }
          return { output: `Backtrace (${frames.length} frames):\n${lines.join("\n")}` };
        },
      }),

      gdbLocals: tool({
        description: "Show local variables in the current stack frame.",
        args: {
          thread: tool.schema.number().optional().describe("Thread ID (default: current)"),
          frame: tool.schema.number().optional().describe("Frame level (default: current)"),
          simple: tool.schema.boolean().optional().describe("Simple values only (default: true)"),
        },
        async execute(args, ctx) {
          const tid = args.thread ?? manager.getState().currentThreadId ?? 1;
          const fid = args.frame ?? manager.getState().currentFrameLevel ?? 0;
          const simple = args.simple !== false;
          const flags = simple ? "--simple-values" : "--all-values";
          const r = await manager.command(`-stack-list-variables --thread ${tid} --frame ${fid} ${flags}`, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };

          const vars = r.resultData?.variables as MiValue[];
          if (!Array.isArray(vars) || vars.length === 0) return { output: "No local variables." };

          const lines = vars.map((v: MiValue) => {
            const e = v as MiTuple;
            const name = e.name as string || "?";
            const val = e.value as string;
            const typ = e.type as string;
            if (val !== undefined) return `  ${name} = ${val}${typ ? `  (${typ})` : ""}`;
            return `  ${name}  (${typ || "?"})`;
          });
          return { output: `Locals (thread ${tid}, frame ${fid}):\n${lines.join("\n")}` };
        },
      }),

      gdbEvaluate: tool({
        description: "Evaluate an expression in the current debugged context.",
        args: {
          expression: tool.schema.string().describe("C/C++ expression to evaluate"),
          thread: tool.schema.number().optional().describe("Thread ID"),
          frame: tool.schema.number().optional().describe("Frame level"),
        },
        async execute(args, ctx) {
          const tid = args.thread ?? manager.getState().currentThreadId;
          const fid = args.frame ?? manager.getState().currentFrameLevel;
          const opts = tid !== undefined ? ` --thread ${tid} --frame ${fid ?? 0}` : "";
          const cmd = `-data-evaluate-expression${opts} ${args.expression}`;
          const r = await manager.command(cmd, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          const val = r.resultData?.value as string || "(no value)";
          return { output: `${args.expression} = ${val}` };
        },
      }),

      gdbSet: tool({
        description: "Set a variable or memory to a new value.",
        args: {
          expression: tool.schema.string().describe("Variable or memory expression"),
          value: tool.schema.string().describe("New value"),
        },
        async execute(args, ctx) {
          const r = await manager.command(`-gdb-set ${args.expression}=${args.value}`, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          return { output: `${args.expression} = ${args.value}` };
        },
      }),

      gdbDisplay: tool({
        description: "Create a variable object for watching across steps (like GDB display).",
        args: {
          expression: tool.schema.string().describe("Expression to watch"),
          name: tool.schema.string().optional().describe("Optional name for the variable object"),
        },
        async execute(args, ctx) {
          const name = args.name || `var${manager.getState().varObjs.length + 1}`;
          const r = await manager.command(`-var-create ${name} * ${args.expression}`, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };

          const info: VarObjInfo = {
            name: (r.resultData?.name as string) || name,
            expression: args.expression,
            type: r.resultData?.type as string,
            value: r.resultData?.value as string,
            numChildren: parseInt((r.resultData?.numchild as string) || "0"),
            hasMore: (r.resultData?.has_more as string) === "1",
          };
          manager.addVarObj(info);

          return { output: `Watching ${args.expression}: ${info.value || "?"} (${info.type || "?"})`, metadata: { varObj: info } };
        },
      }),

      gdbDisplayList: tool({
        description: "List all watched variable objects.",
        args: {},
        async execute(_args, ctx) {
          const state = manager.getState();
          if (state.varObjs.length === 0) return { output: "No watched variables." };
          const lines = state.varObjs.map((v) => `  ${v.name}: ${v.expression} = ${v.value || "?"} (${v.type || "?"})`);
          return { output: `Display:\n${lines.join("\n")}` };
        },
      }),

      gdbDisplayDelete: tool({
        description: "Delete a watched variable object.",
        args: {
          name: tool.schema.string().describe("Variable object name (from gdb-display)"),
        },
        async execute(args, ctx) {
          const r = await manager.command(`-var-delete ${args.name}`, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          manager.removeVarObj(args.name);
          return { output: `Deleted display ${args.name}` };
        },
      }),

      gdbDisplayUpdate: tool({
        description: "Update all watched variable objects with current values.",
        args: {
          name: tool.schema.string().optional().describe("Specific variable object name to update (default: all)"),
        },
        async execute(args, ctx) {
          const state = manager.getState();
          const names = args.name ? [args.name] : state.varObjs.map((v) => v.name);
          if (names.length === 0) return { output: "No watched variables." };

          const results: string[] = [];
          for (const name of names) {
            const r = await manager.command(`-var-update ${name}`, true);
            if (r.resultClass === "error") {
              results.push(`  ${name}: ERROR - ${r.resultData.msg}`);
              continue;
            }
            const changelist = r.resultData?.changelist as MiValue[];
            if (Array.isArray(changelist) && changelist.length > 0) {
              for (const change of changelist) {
                const c = change as MiTuple;
                const vname = c.name as string;
                const val = c.value as string;
                const in_scope = (c.in_scope as string) !== "false";
                if (in_scope && val !== undefined) {
                  results.push(`  ${vname}: ${val}`);
                  const vo = state.varObjs.find((v) => v.name === vname || v.name === name);
                  if (vo) vo.value = val;
                } else if (!in_scope) {
                  results.push(`  ${vname}: <out of scope>`);
                }
              }
            } else {
              const ev = await manager.command(`-var-evaluate-expression ${name}`, true);
              if (ev.resultClass === "done" && ev.resultData?.value) {
                const val = ev.resultData.value as string;
                results.push(`  ${name}: ${val}`);
                const vo = state.varObjs.find((v) => v.name === name);
                if (vo) vo.value = val;
              }
            }
          }
          saveState(state);
          return { output: results.length > 0 ? `Updated:\n${results.join("\n")}` : "No changes." };
        },
      }),

      gdbThreads: tool({
        description: "List all threads in the debugged process.",
        args: {},
        async execute(_args, ctx) {
          await manager.syncThreads();
          const threads = manager.getState().threads;
          if (threads.length === 0) return { output: "No threads (program not running)." };
          const cur = manager.getState().currentThreadId;
          const lines = threads.map((t) => {
            const marker = t.id === cur ? "*" : " ";
            const func = t.frame?.func || "??";
            const file = t.frame?.file ? ` at ${t.frame.file}:${t.frame.line}` : t.frame?.from ? ` from ${t.frame.from}` : "";
            return `  ${marker} Thread ${t.id} (${t.targetId}): ${func}${file} [${t.state}]`;
          });
          return { output: `Threads:\n${lines.join("\n")}` };
        },
      }),

      gdbSelectThread: tool({
        description: "Switch to a specific thread for subsequent commands.",
        args: {
          id: tool.schema.number().describe("Thread ID to select"),
        },
        async execute(args, ctx) {
          const r = await manager.command(`-thread-select ${args.id}`, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          manager.setCurrentThread(args.id);
          return { output: `Switched to thread ${args.id}` };
        },
      }),

      gdbSelectFrame: tool({
        description: "Select a stack frame in the current thread for inspection.",
        args: {
          level: tool.schema.number().describe("Frame level (0 is innermost)"),
        },
        async execute(args, ctx) {
          const r = await manager.command(`-stack-select-frame ${args.level}`, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          manager.setCurrentFrame(args.level);
          return { output: `Switched to frame #${args.level}` };
        },
      }),

      gdbDisassemble: tool({
        description: "Disassemble code at a location or around the current PC.",
        args: {
          location: tool.schema.string().optional().describe("Function or address range (e.g. 'main', 'main,+20')"),
          count: tool.schema.number().optional().describe("Number of instructions (default: 20)"),
          mode: tool.schema.enum(["mixed", "source", "assembly"]).optional().describe("Display mode (default: assembly)"),
        },
        async execute(args, ctx) {
          const state = manager.getState();
          let loc = args.location;
          if (!loc) {
            const r = await manager.command("-stack-info-frame", true);
            if (r.resultClass === "done" && r.resultData?.frame) {
              const f = r.resultData.frame as MiTuple;
              loc = f.addr as string || f.func as string;
            }
            if (!loc) return { output: "Cannot determine current location. Specify --location." };
          }

          const modeMap: Record<string, string> = { assembly: "0", mixed: "1", source: "2" };
          const mode = modeMap[args.mode || "assembly"] || "0";
          const count = args.count ?? 20;

          const miCmd = `-data-disassemble -s ${loc} -e ${loc}+${count * 4} -- ${mode}`;
          const r2 = await manager.command(miCmd, true);
          if (r2.resultClass === "error") return { output: `ERROR: ${r2.resultData.msg}` };

          const asm = r2.resultData?.asm_insns as MiValue[];
          if (!Array.isArray(asm)) return { output: "No disassembly available." };

          const lines: string[] = [];
          for (const srcBlock of asm) {
            const block = srcBlock as MiTuple;
            const file = block.file as string;
            const line = block.line as string;
            const insns = block.insns as MiValue[];
            if (file && mode !== "assembly") lines.push(`${file}:${line}`);
            if (Array.isArray(insns)) {
              for (const insn of insns) {
                const i = insn as MiTuple;
                const addr = i.address as string || "";
                const funcName = i["func-name"] as string;
                const offset = i.offset as string;
                const inst = i.inst as string || "";
                const func = funcName ? `<${funcName}+${offset}>` : "";
                lines.push(`  ${addr}  ${func}  ${inst}`);
              }
            }
          }
          return { output: `Disassembly of ${loc}:\n${lines.join("\n")}` };
        },
      }),

      gdbRegisters: tool({
        description: "Print CPU register values for the current thread/frame.",
        args: {
          group: tool.schema.string().optional().describe("Register group (e.g. 'general', 'float', 'vector')"),
        },
        async execute(args, ctx) {
          const cmd = args.group ? `-data-list-register-values x ${args.group}` : "-data-list-register-names";
          const r = await manager.command(cmd, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          const names = r.resultData?.registerNames as MiValue[];
          if (!Array.isArray(names)) return { output: "Register data:\n" + manager.formatResponse(r) };

          const vals = await manager.command("-data-list-register-values x", true);
          if (vals.resultClass === "error") return { output: `ERROR: ${vals.resultData.msg}` };
          const valArr = vals.resultData?.["register-values"] as MiValue[];

          if (!Array.isArray(valArr)) return { output: "No register values." };

          const lines = valArr.map((v: MiValue) => {
            const e = v as MiTuple;
            const num = parseInt((e.number as string) || "0");
            const val = e.value as string || "??";
            const name = num < names.length ? (names[num] as string) : `r${num}`;
            return `  ${name}: ${val}`;
          });
          return { output: `Registers:\n${lines.join("\n")}` };
        },
      }),

      gdbStatus: tool({
        description: "Show current GDB session status, loaded binary, breakpoints, threads.",
        args: {},
        async execute(_args, ctx) {
          const s = manager.getState();
          const alive = manager.isRunning();
          const lines: string[] = [
            `GDB running: ${alive}`,
            `Status: ${s.status}`,
            `Binary: ${s.binary || "(none)"}`,
            `Args: ${s.args || "(none)"}`,
            `CWD: ${s.cwd || "(default)"}`,
            `Breakpoints: ${s.breakpoints.length}`,
            `Watch variables: ${s.varObjs.length}`,
            `Current thread: ${s.currentThreadId ?? "?"}`,
            `Current frame: ${s.currentFrameLevel ?? 0}`,
          ];
          if (s.lastStopReason) lines.push(`Last stop: ${s.lastStopReason}`);
          if (s.lastSignal) lines.push(`Last signal: ${s.lastSignal}`);
          return { output: lines.join("\n") };
        },
      }),

      gdbArgs: tool({
        description: "Set program arguments for the next run.",
        args: {
          args: tool.schema.string().describe("Command-line arguments for the debugged program"),
        },
        async execute(args, ctx) {
          const r = await manager.command(`-exec-arguments ${args.args}`);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          manager.setArgs(args.args);
          return { output: `Arguments set: ${args.args}` };
        },
      }),

      gdbCwd: tool({
        description: "Set the working directory for the debugged program.",
        args: {
          dir: tool.schema.string().describe("Working directory path"),
        },
        async execute(args, ctx) {
          const r = await manager.command(`-environment-cd ${args.dir}`);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          return { output: `Working directory: ${args.dir}` };
        },
      }),

      gdbEnv: tool({
        description: "Set an environment variable for the debugged program.",
        args: {
          name: tool.schema.string().describe("Environment variable name"),
          value: tool.schema.string().describe("Environment variable value"),
        },
        async execute(args, ctx) {
          const r = await manager.command(`-gdb-set environment ${args.name} ${args.value}`);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          return { output: `${args.name}=${args.value}` };
        },
      }),

      gdbSignal: tool({
        description: "Send a signal to the debugged program.",
        args: {
          signal: tool.schema.string().describe("Signal name or number (e.g. 'SIGUSR1', 'SIGINT', '15')"),
        },
        async execute(args, ctx) {
          const r = await manager.command(`-exec-interrupt --signal ${args.signal}`);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          return { output: `Sent ${args.signal}` };
        },
      }),

      gdbAttach: tool({
        description: "Attach GDB to a running process by PID.",
        args: {
          pid: tool.schema.number().describe("Process ID to attach to"),
        },
        async execute(args, ctx) {
          const r = await manager.command(`-target-attach ${args.pid}`);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          return { output: `Attached to PID ${args.pid}` };
        },
      }),

      gdbDetach: tool({
        description: "Detach GDB from the debugged process (process continues running).",
        args: {},
        async execute(_args, ctx) {
          const r = await manager.command("-target-detach");
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          return { output: "Detached from process." };
        },
      }),

      gdbCore: tool({
        description: "Generate a core dump of the debugged process.",
        args: {
          path: tool.schema.string().optional().describe("Output path for core file (default: /tmp/core)"),
        },
        async execute(args, ctx) {
          const path = args.path || "/tmp/core";
          const r = await manager.command(`-gdb-generate-core ${path}`, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          return { output: `Core dumped to ${path}` };
        },
      }),

      gdbSource: tool({
        description: "Source (execute) a GDB script file.",
        args: {
          file: tool.schema.string().describe("Path to GDB script file"),
        },
        async execute(args, ctx) {
          const r = await manager.command(`-source ${args.file}`);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          return { output: `Sourced ${args.file}` };
        },
      }),

      gdbPstack: tool({
        description: "Print stack traces for all threads (like 'thread apply all bt').",
        args: {
          count: tool.schema.number().optional().describe("Number of frames per thread (default: all)"),
        },
        async execute(args, ctx) {
          await manager.syncThreads();
          const threads = manager.getState().threads;
          if (threads.length === 0) return { output: "No threads (program not running)." };

          const output: string[] = [];
          for (const t of threads) {
            const r = await manager.command(`--thread ${t.id} -stack-list-frames${args.count ? ` 0 ${args.count - 1}` : ""}`, true);
            if (r.resultClass === "error") {
              output.push(`Thread ${t.id} (${t.targetId}): ERROR - ${r.resultData.msg}`);
              continue;
            }
            const stack = r.resultData?.stack as MiTuple;
            const frames = stack?.frame as MiValue[] || [];
            output.push(`Thread ${t.id} (${t.targetId}):`);
            for (let i = 0; i < frames.length; i++) {
              const f = frames[i] as MiTuple;
              const func = f.func as string || "??";
              const file = f.file as string || f.from as string || "??";
              const line = f.line as string;
              output.push(`  #${i}  ${func} at ${file}${line ? `:${line}` : ""}`);
            }
          }
          return { output: output.join("\n") };
        },
      }),

      gdbRecord: tool({
        description: "Start or stop reverse execution recording.",
        args: {
          action: tool.schema.enum(["start", "stop"]).describe("Start or stop recording"),
        },
        async execute(args, ctx) {
          const cmd = args.action === "start" ? "target record-full" : "target record-stop";
          const r = await manager.command(`-interpreter-exec console "${cmd}"`, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg || manager.formatResponse(r)}` };
          return { output: `Recording ${args.action === "start" ? "started" : "stopped"}.` };
        },
      }),

      gdbReverse: tool({
        description: "Reverse-step or reverse-continue (requires recording).",
        args: {
          command: tool.schema.enum(["reverse-step", "reverse-next", "reverse-continue", "reverse-finish"]).describe("Reverse execution command"),
        },
        async execute(args, ctx) {
          const r = await manager.command(`-exec-${args.command.replace("reverse-", "")} --reverse`, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          const s = manager.getState();
          const lines = manager.formatStoppedInfo(r, s);
          return { output: lines.join("\n") };
        },
      }),

      gdbFind: tool({
        description: "Search memory for a pattern.",
        args: {
          pattern: tool.schema.string().describe("Pattern to search for (hex bytes or string)"),
          start: tool.schema.string().optional().describe("Start address (default: $sp)"),
          end: tool.schema.string().optional().describe("End address (default: $sp + 4096)"),
        },
        async execute(args, ctx) {
          const start = args.start || "$sp";
          const end = args.end || "$sp + 4096";
          const cmd = `find ${start},${end},${args.pattern}`;
          const r = await manager.command(`-interpreter-exec console "${cmd}"`, true);
          const output = manager.formatResponse(r) || r.raw;
          return { output: output || "No matches." };
        },
      }),

      gdbMem: tool({
        description: "Read memory at an address and display as hex/ASCII.",
        args: {
          address: tool.schema.string().describe("Address expression (e.g. '0x7fff...', '$rbp-0x20', '&variable')"),
          count: tool.schema.number().optional().describe("Number of bytes (default: 64)"),
        },
        async execute(args, ctx) {
          const count = args.count ?? 64;
          const r = await manager.command(`-data-read-memory-bytes ${args.address} ${count}`, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData?.msg as string || r.raw.substring(0, 300)}` };
          const mem = r.resultData?.memory as MiValue[];
          if (!Array.isArray(mem)) return { output: "No memory data." };

          const out: string[] = [];
          for (const block of mem) {
            const b = block as MiTuple;
            const begin = parseInt((b.begin as string) || "0");
            const contents = b.contents as MiValue[];
            if (!Array.isArray(contents)) {
              const addrStr = `0x${begin.toString(16).padStart(16, "0")}`;
              const bytes = contents as unknown as MiValue[];
              if (Array.isArray(bytes)) {
                const hex = bytes.map((bb) => typeof bb === "string" ? bb : String(bb)).join(" ");
                out.push(`  ${addrStr}: ${hex}`);
              }
              continue;
            }

            for (const entry of contents) {
              const e = entry as MiTuple;
              const bytes = Array.isArray(e.bytes as MiValue[]) ? (e.bytes as MiValue[]) : (e.data as MiValue[] as MiValue[]) || [];
              const ascii = (e.ascii as string) || (e.data as string) || "";

              let addrVal = begin;
              const hexParts: string[] = [];
              for (const b2 of bytes) {
                if (typeof b2 === "object" && b2 !== null) {
                  const b3 = b2 as MiTuple;
                  const v = (b3.data as string) || (b3.value as string);
                  if (v) hexParts.push(v);
                } else {
                  hexParts.push(String(b2));
                }
              }
              if (hexParts.length === 0) {
                out.push(`  0x${addrVal.toString(16).padStart(16, "0")}: ${ascii}`);
                continue;
              }
              const hex = hexParts.join(" ");
              const addrStr = `0x${addrVal.toString(16).padStart(16, "0")}`;
              const pad = hex.length < 48 ? hex + " ".repeat(48 - hex.length) : hex;
              out.push(`  ${addrStr}: ${pad}  ${ascii}`);
            }
          }
          return { output: `Memory at ${args.address} (${count} bytes):\n${out.join("\n")}` };
        },
      }),

      gdbJump: tool({
        description: "Jump to a specific address/line and continue execution from there.",
        args: {
          location: tool.schema.string().describe("Location to jump to (address, function, or file:line)"),
        },
        async execute(args, ctx) {
          const r = await manager.command(`-exec-jump ${args.location}`, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          return { output: `Jumped to ${args.location}` };
        },
      }),

      gdbReturn: tool({
        description: "Force-return from the current function with a value.",
        args: {
          expression: tool.schema.string().optional().describe("Return value expression (omit for void return)"),
        },
        async execute(args, ctx) {
          const cmd = args.expression ? `-exec-return ${args.expression}` : "-exec-return";
          const r = await manager.command(cmd, true);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          return { output: `Returned${args.expression ? ` ${args.expression}` : ""}` };
        },
      }),

      gdbExit: tool({
        description: "Terminate GDB and clean up the debugging session.",
        args: {},
        async execute(_args, ctx) {
          const msg = manager.stop();
          return { output: msg };
        },
      }),

      gdbRaw: tool({
        description: "Send a raw MI command to GDB (for advanced use). Returns the full GDB response text.",
        args: {
          command: tool.schema.string().describe("GDB/MI command (without token prefix, e.g. '-stack-info-depth')"),
        },
        async execute(args, ctx) {
          const r = await manager.command(args.command);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          return { output: r.raw || manager.formatResponse(r) };
        },
      }),

      gdbInfo: tool({
        description: "Run a general GDB 'info' command (e.g. 'info threads', 'info functions', 'info shared').",
        args: {
          what: tool.schema.string().describe("What to get info about (e.g. 'threads', 'functions', 'shared', 'args', 'locals', 'registers')"),
        },
        async execute(args, ctx) {
          const cliCmd = `info ${args.what.replace(/"/g, '\\"')}`;
          const r = await manager.command(`-interpreter-exec console "${cliCmd}"`);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          const consoleOut = r.records
            .filter((rec): rec is MiRecord & { type: "console" | "target" | "log"; text: string } =>
              (rec.type === "console" || rec.type === "target" || rec.type === "log") && rec.text !== undefined
            )
            .map((rec) => rec.text)
            .join("");
          return { output: consoleOut || r.raw };
        },
      }),

      gdbExec: tool({
        description: "Execute an arbitrary GDB CLI command (not MI). Useful for custom GDB commands.",
        args: {
          command: tool.schema.string().describe("GDB CLI command (e.g. 'print myvar', 'list', 'frame 2')"),
        },
        async execute(args, ctx) {
          const r = await manager.command(`-interpreter-exec console "${args.command.replace(/"/g, '\\"')}"`);
          if (r.resultClass === "error") return { output: `ERROR: ${r.resultData.msg}` };
          const console = r.records
            .filter((rec): rec is MiRecord & { type: "console" | "target" | "log"; text: string } =>
              (rec.type === "console" || rec.type === "target" || rec.type === "log") && rec.text !== undefined
            )
            .map((rec) => rec.text)
            .join("");
          return { output: console || `OK (${r.resultClass})` };
        },
      }),

    },
  };
}
