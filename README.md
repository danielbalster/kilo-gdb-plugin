# @dbalster/gdb-plugin

> **100% AI-generated proof-of-concept.** This project was requested as: build a
> TypeScript plugin that uses the GDB/MI protocol and exposes all debugging tools
> needed for an AI agent to debug programs with GDB. Every line of code was
> written by an AI language model.

A [Kilo](https://kilo.ai) / OpenCode TypeScript plugin that provides a full GDB/MI debugging interface via GDB's Machine Interface protocol.

## Features

- **30+ debugging tools**: init, load, run, continue, interrupt, step, next, finish, breakpoints, watchpoints, catchpoints, backtrace, locals, evaluate, memory, registers, disassemble, threads, and more
- **GDB/MI protocol**: Full MI tokenizer/parser with async record handling
- **State persistence**: Session state saved to `/tmp/kilo-gdb/state.json` across restarts
- **Process management**: Start, stop, attach, detach, and core dump support
- **Reverse execution**: record/reverse-step/next/continue/finish
- **Variable objects**: Create and watch expressions across debugging steps

## Installation

```bash
npm install -g @dbalster/gdb-plugin
```

## Usage in Kilo/OpenCode

Copy or symlink `gdb.ts` into your `.kilo/plugins/` directory:

```bash
mkdir -p ~/project/.kilo/plugins
cp node_modules/@dbalster/gdb-plugin/dist/gdb.js ~/project/.kilo/plugins/gdb.js
```

Then reference it in `.kilo/kilo.json`:

```json
{
  "plugins": ["./plugins/gdb.js"]
}
```

## Tools Provided

| Tool | Description |
|------|-------------|
| `gdbInit` | Start GDB with a binary executable |
| `gdbLoad` | Load a new binary/symbol file |
| `gdbRun` | Run/restart the debugged program |
| `gdbContinue` | Continue execution |
| `gdbInterrupt` | Interrupt the running program |
| `gdbStep` | Step into next source line |
| `gdbNext` | Step over next source line |
| `gdbFinish` | Step out of current function |
| `gdbBreak` | Set a breakpoint |
| `gdbBreakpointList` | List all breakpoints |
| `gdbBreakpointDelete` | Delete breakpoint(s) |
| `gdbBreakpointEnable` / `gdbBreakpointDisable` | Toggle breakpoints |
| `gdbBreakpointCondition` | Set/clear breakpoint condition |
| `gdbWatch` | Set a watchpoint |
| `gdbCatch` | Set a catchpoint |
| `gdbBacktrace` | Print call stack |
| `gdbLocals` | Show local variables |
| `gdbEvaluate` | Evaluate an expression |
| `gdbSet` | Set a variable/memory value |
| `gdbDisplay` / `gdbDisplayList` / `gdbDisplayDelete` / `gdbDisplayUpdate` | Variable objects |
| `gdbThreads` / `gdbSelectThread` | Thread management |
| `gdbSelectFrame` | Select stack frame |
| `gdbDisassemble` | Disassemble code |
| `gdbRegisters` | Show CPU registers |
| `gdbStatus` | Session status overview |
| `gdbArgs` / `gdbCwd` / `gdbEnv` | Program setup |
| `gdbSignal` | Send a signal |
| `gdbAttach` / `gdbDetach` | Process attach/detach |
| `gdbCore` | Generate core dump |
| `gdbSource` | Source a GDB script |
| `gdbPstack` | Stack traces for all threads |
| `gdbRecord` / `gdbReverse` | Reverse execution |
| `gdbFind` / `gdbMem` | Memory search and dump |
| `gdbJump` / `gdbReturn` | Execution control flow |
| `gdbExit` | Terminate GDB session |
| `gdbRaw` / `gdbInfo` / `gdbExec` | Raw/CLI command access |

## Requirements

- [GDB](https://www.gnu.org/software/gdb/) installed on the system
- A compiled binary with debug symbols (`-g` flag)

## License

MIT
