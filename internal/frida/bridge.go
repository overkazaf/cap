package frida

// pythonBridgeScript is an embedded zero-dependency Python 3 Frida session host.
// It communicates over line-delimited JSON (NDJSON) on stdout and accepts live
// control commands on stdin (hot-reload, resume, eval, detach).
const pythonBridgeScript = `#!/usr/bin/env python3
import json
import os
import signal
import sys
import threading
import time
import traceback

try:
    import frida
except Exception as exc:
    sys.stdout.write(json.dumps({
        "type": "error",
        "description": "Failed to import frida Python module: " + str(exc),
    }) + "\n")
    sys.stdout.flush()
    sys.exit(2)

_write_lock = threading.Lock()
_stop_event = threading.Event()
_state = {
    "device": None,
    "session": None,
    "script": None,
    "pid": None,
    "paused": False,
}


def emit(obj):
    with _write_lock:
        try:
            sys.stdout.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
            sys.stdout.flush()
        except Exception:
            pass


def get_device(serial, remote_host):
    if remote_host:
        dm = frida.get_device_manager()
        return dm.add_remote_device(remote_host)
    if serial:
        try:
            return frida.get_device(serial, timeout=5)
        except Exception:
            for d in frida.enumerate_devices():
                if d.id == serial:
                    return d
            raise
    return frida.get_usb_device(timeout=5)


def resolve_attach_target(device, target):
    t = str(target).strip()
    if t.isdigit():
        return int(t)
    # Prefer matching running Android app by package identifier -> pid
    try:
        for app in device.enumerate_applications():
            if app.identifier == t or app.name == t:
                if app.pid and app.pid > 0:
                    return app.pid
    except Exception:
        pass
    try:
        for proc in device.enumerate_processes():
            if proc.name == t:
                return proc.pid
    except Exception:
        pass
    return t


def on_script_message(message, data):
    msg_type = message.get("type", "unknown")
    data_hex = ""
    if data:
        try:
            raw = bytes(data)
            if len(raw) > 512:
                data_hex = raw[:512].hex() + "...(" + str(len(raw)) + " bytes)"
            else:
                data_hex = raw.hex()
        except Exception:
            pass
    if msg_type == "send":
        emit({
            "type": "send",
            "payload": message.get("payload"),
            "data_hex": data_hex,
        })
    elif msg_type == "error":
        emit({
            "type": "error",
            "description": message.get("description", "Frida script error"),
            "stack": message.get("stack", ""),
            "line": message.get("lineNumber"),
            "column": message.get("columnNumber"),
        })
    else:
        emit({"type": "console", "level": "info", "message": str(message)})


def on_script_log(level, text):
    emit({"type": "console", "level": str(level or "info"), "message": str(text)})


def load_script(session, code):
    prev = _state.get("script")
    if prev is not None:
        try:
            prev.unload()
        except Exception:
            pass
        _state["script"] = None

    script = session.create_script(code)
    script.on("message", on_script_message)
    try:
        script.set_log_handler(on_script_log)
    except Exception:
        pass
    script.load()
    _state["script"] = script
    return script


def on_detached(reason, crash):
    detail = str(reason)
    if crash is not None:
        try:
            detail = detail + ": " + getattr(crash, "summary", str(crash))
        except Exception:
            pass
    emit({"type": "lifecycle", "event": "detached", "reason": detail})
    _stop_event.set()


def stdin_loop():
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            cmd = json.loads(line)
        except Exception as exc:
            emit({"type": "error", "description": "Invalid control command: " + str(exc)})
            continue

        action = cmd.get("cmd", "")
        if action == "reload":
            code = cmd.get("code", "")
            session = _state.get("session")
            if session is None:
                emit({"type": "error", "description": "Cannot hot-reload: no active session"})
                continue
            try:
                load_script(session, code)
                emit({"type": "lifecycle", "event": "reloaded"})
            except Exception as exc:
                emit({"type": "error", "description": "Hot-reload failed: " + str(exc), "stack": traceback.format_exc()})
        elif action == "resume":
            dev = _state.get("device")
            pid = _state.get("pid")
            if dev is not None and pid:
                try:
                    dev.resume(pid)
                    _state["paused"] = False
                    emit({"type": "lifecycle", "event": "resumed", "pid": pid})
                except Exception as exc:
                    emit({"type": "error", "description": "Resume failed: " + str(exc)})
        elif action == "detach":
            _stop_event.set()
            break
    _stop_event.set()


def run_ps(serial, remote_host):
    device = get_device(serial, remote_host)
    entries = []
    seen_pids = set()
    try:
        for app in device.enumerate_applications():
            pid = int(getattr(app, "pid", 0) or 0)
            if pid > 0:
                seen_pids.add(pid)
            entries.append({
                "pid": pid,
                "name": getattr(app, "name", "") or getattr(app, "identifier", ""),
                "identifier": getattr(app, "identifier", ""),
                "running": pid > 0,
                "source": "frida",
            })
    except Exception:
        pass
    try:
        for proc in device.enumerate_processes():
            pid = int(getattr(proc, "pid", 0) or 0)
            if pid in seen_pids:
                continue
            entries.append({
                "pid": pid,
                "name": getattr(proc, "name", ""),
                "identifier": "",
                "running": True,
                "source": "frida",
            })
    except Exception:
        pass
    sys.stdout.write(json.dumps(entries, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--ps":
        serial = sys.argv[2] if len(sys.argv) > 2 else ""
        remote_host = sys.argv[3] if len(sys.argv) > 3 else ""
        try:
            run_ps(serial, remote_host)
        except Exception as exc:
            sys.stderr.write(str(exc) + "\n")
            sys.exit(1)
        return

    if len(sys.argv) < 2:
        emit({"type": "error", "description": "Missing bridge config file path"})
        sys.exit(1)

    with open(sys.argv[1], "r", encoding="utf-8") as fh:
        cfg = json.load(fh)

    serial = cfg.get("serial", "")
    remote_host = cfg.get("remote_host", "")
    target = cfg.get("target", "")
    mode = cfg.get("mode", "attach")
    no_pause = bool(cfg.get("no_pause", True))
    script_code = cfg.get("script_code", "")

    def _sig_handler(_signum, _frame):
        _stop_event.set()

    signal.signal(signal.SIGTERM, _sig_handler)
    signal.signal(signal.SIGINT, _sig_handler)

    try:
        emit({"type": "lifecycle", "event": "connecting", "target": target, "mode": mode})
        device = get_device(serial, remote_host)
        _state["device"] = device

        pid = 0
        if mode == "spawn":
            pid = device.spawn([target])
            _state["pid"] = pid
            _state["paused"] = True
            session = device.attach(pid)
        else:
            resolved = resolve_attach_target(device, target)
            session = device.attach(resolved)
            if isinstance(resolved, int):
                pid = resolved
            else:
                pid = int(getattr(session, "pid", 0) or 0)
            _state["pid"] = pid

        _state["session"] = session
        session.on("detached", on_detached)

        emit({"type": "lifecycle", "event": "attached", "pid": pid, "target": target, "paused": _state["paused"]})

        if script_code.strip():
            load_script(session, script_code)
            emit({"type": "lifecycle", "event": "loaded", "pid": pid})

        if mode == "spawn" and no_pause and pid:
            device.resume(pid)
            _state["paused"] = False
            emit({"type": "lifecycle", "event": "resumed", "pid": pid})

        t = threading.Thread(target=stdin_loop, daemon=True)
        t.start()

        while not _stop_event.is_set():
            _stop_event.wait(0.25)

    except Exception as exc:
        emit({
            "type": "error",
            "description": str(exc),
            "stack": traceback.format_exc(),
        })
        sys.exit(1)
    finally:
        try:
            if _state.get("script") is not None:
                _state["script"].unload()
        except Exception:
            pass
        try:
            if _state.get("session") is not None:
                _state["session"].detach()
        except Exception:
            pass
        emit({"type": "lifecycle", "event": "exited"})


if __name__ == "__main__":
    main()
`

// cliStructuredPrefix marks structured JSON lines emitted by scripts when
// running under the fallback `frida` CLI driver so cap can still render
// structured Hook cards without Python bridge.
const cliStructuredPrefix = "[CAP_EVENT] "

// wrapScriptForCLI prepends a tiny non-intrusive shim when executing via
// fallback `frida` CLI so send() payloads are also mirrored with
// [CAP_EVENT] JSON lines for structured parsing.
func wrapScriptForCLI(code string) string {
	shim := `/* cap frida-cli structured event shim */
(function(){
  if (typeof globalThis.__capOrigSend === 'undefined' && typeof send === 'function') {
    globalThis.__capOrigSend = send;
    globalThis.send = function(payload, data) {
      try {
        console.log('[CAP_EVENT] ' + JSON.stringify(payload));
      } catch (_) {}
      return globalThis.__capOrigSend(payload, data);
    };
  }
})();
`
	return shim + "\n" + code
}
