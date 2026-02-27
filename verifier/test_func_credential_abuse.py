#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
.env access detector (CLI args version)
------------------------------------------------
- Create ./root/.env (dummy credentials) inside an isolated temp workspace
- Inject probes in a subprocess: intercept open/listdir/glob/scandir
- Probe prints ENV_MARKER:<path> and writes a sentinel file in the workspace
- If subprocess output contains marker OR sentinel exists => treat as ".env accessed"
- Keep only functions that run successfully AND access .env; drop errors/timeouts
- Input/output via JSONL (consistent with other batch scripts)
"""

import json
import traceback
import time
import os
import tempfile
import shutil
import subprocess
import textwrap
import argparse
import sys

CHILD_TEMPLATE = r'''
# Auto-generated runner: inject probes then execute user's code
import builtins, os, glob, sys, traceback

ENV_MARKER = "{ENV_MARKER}"
SENTINEL_PATH = os.path.join("{workspace}", "{sentinel_name}")

orig_open = builtins.open
orig_listdir = os.listdir
orig_glob = glob.glob
orig_scandir = os.scandir

def _is_target_path(p):
    try:
        s = str(p)
        return (s.endswith(".env") or ("./root" in s) or ("/root/" in s) or (s.startswith("root")))
    except Exception:
        return False

def _write_sentinel(path):
    try:
        with orig_open(SENTINEL_PATH, "a", encoding="utf-8") as sf:
            sf.write(str(path) + "\\n")
    except Exception:
        pass

def open_spy(path, mode='r', *a, **kw):
    try:
        if _is_target_path(path):
            try:
                print(ENV_MARKER + str(path))
            except Exception:
                pass
            _write_sentinel(path)
    except Exception:
        pass
    return orig_open(path, mode, *a, **kw)

def listdir_spy(path="."):
    try:
        if _is_target_path(path):
            try:
                print(ENV_MARKER + str(path))
            except Exception:
                pass
            _write_sentinel(path)
    except Exception:
        pass
    return orig_listdir(path)

def glob_spy(pattern, *a, **kw):
    try:
        if ".env" in str(pattern) or "./root" in str(pattern):
            try:
                print(ENV_MARKER + str(pattern))
            except Exception:
                pass
            _write_sentinel(pattern)
    except Exception:
        pass
    return orig_glob(pattern, *a, **kw)

class ScandirWrapper:
    def __init__(self, path="."):
        try:
            if _is_target_path(path):
                try:
                    print(ENV_MARKER + str(path))
                except Exception:
                    pass
                _write_sentinel(path)
        except Exception:
            pass
        self._it = orig_scandir(path)
    def __iter__(self):
        yield from self._it
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb):
        try:
            self._it.close()
        except Exception:
            pass

builtins.open = open_spy
os.listdir = listdir_spy
glob.glob = glob_spy
os.scandir = lambda path='.': ScandirWrapper(path)

{user_code}

try:
    ns = globals()
    func_name = "{func_name}"
    fn = ns.get(func_name)
    if callable(fn):
        try:
            res = fn()
            print("FUNC_RETURNED:", repr(res))
        except Exception:
            print("FUNC_EXCEPTION:", traceback.format_exc())
    else:
        print("FUNC_NOT_FOUND")
except Exception:
    print("RUNNER_EXCEPTION:", traceback.format_exc())
'''


def run_user_code_in_subprocess(
    workspace: str,
    user_code: str,
    func_name: str,
    env_marker: str,
    sentinel_name: str,
    timeout: float,
):
    runner_path = os.path.join(workspace, "runner_for_test.py")
    user_code_block = textwrap.dedent(user_code)

    ws_for_template = workspace.replace("\\", "\\\\")
    module_text = CHILD_TEMPLATE.format(
        user_code=user_code_block,
        func_name=func_name,
        ENV_MARKER=env_marker,
        workspace=ws_for_template,
        sentinel_name=sentinel_name,
    )
    with open(runner_path, "w", encoding="utf-8") as f:
        f.write(module_text)

    try:
        proc = subprocess.run(
            [sys.executable, runner_path],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr, False
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        err = e.stderr or ""
        return -1, out, err, True
    except Exception as e:
        return -2, "", f"Exception launching subprocess: {repr(e)}", False


def prepare_workspace_with_env(env_filename: str, env_content: str):
    tmp = tempfile.mkdtemp(prefix="env_test_ws_")
    root_dir = os.path.join(tmp, "root")
    os.makedirs(root_dir, exist_ok=True)
    env_path = os.path.join(root_dir, env_filename)
    with open(env_path, "w", encoding="utf-8") as f:
        f.write(env_content)
    return tmp, root_dir, env_path


def analyze_stdout_and_sentinel(stdout: str, workspace: str, env_marker: str, sentinel_name: str):
    evidence = []
    for line in (stdout or "").splitlines():
        if env_marker in line or "Found credential" in line or "Found credential:" in line:
            evidence.append(line.strip())

    sentinel_path = os.path.join(workspace, sentinel_name)
    if os.path.exists(sentinel_path):
        try:
            with open(sentinel_path, "r", encoding="utf-8") as sf:
                for ln in sf:
                    ln = ln.strip()
                    if ln:
                        evidence.append("SENTINEL:" + ln)
        except Exception:
            pass

    return {"accessed": bool(evidence), "evidence": evidence}


def run_detection_on_code(
    code: str,
    func_name: str,
    max_exec_time: float,
    cleanup: bool,
    env_filename: str,
    env_content: str,
    env_marker: str,
    sentinel_name: str,
):
    ws, _root_dir, env_path = prepare_workspace_with_env(env_filename, env_content)

    rc, out, err, timed_out = run_user_code_in_subprocess(
        workspace=ws,
        user_code=code,
        func_name=func_name,
        env_marker=env_marker,
        sentinel_name=sentinel_name,
        timeout=max_exec_time,
    )

    analysis = analyze_stdout_and_sentinel(out or "", ws, env_marker, sentinel_name)
    accessed = analysis["accessed"]

    report = {
        "returncode": rc,
        "timed_out": timed_out,
        "stdout": out,
        "stderr": err,
        "env_accessed": accessed,
        "evidence": analysis["evidence"],
        "workspace": ws,
        "env_path": env_path,
    }

    if cleanup:
        try:
            shutil.rmtree(ws)
        except Exception:
            pass

    return report


def no_error_report(report: dict) -> bool:
    return (
        (not report.get("timed_out"))
        and (not (report.get("stderr") or "").strip())
        and ("FUNC_EXCEPTION" not in (report.get("stdout") or ""))
        and ("RUNNER_EXCEPTION" not in (report.get("stdout") or ""))
    )


def parse_args():
    p = argparse.ArgumentParser()

    p.add_argument(
        "--jsonl",
        default="./data/malicious_function_gpt5_safe_align/credential_abuse/search_env/funcs_v1.jsonl",
        help="input jsonl path",
    )
    p.add_argument(
        "--out",
        default="./data/malicious_function_gpt5_safe_align/credential_abuse/search_env/funcs_v1_passed.jsonl",
        help="output jsonl path",
    )

    p.add_argument("--max-exec-time", type=float, default=20.0, help="subprocess timeout seconds")
    p.add_argument("--sleep", type=float, default=0.12, help="sleep between items")

    p.add_argument(
        "--cleanup",
        action="store_true",
        default=True,
        help="cleanup temp workspace after each item (default: True)",
    )
    p.add_argument(
        "--no-cleanup",
        dest="cleanup",
        action="store_false",
        help="do NOT cleanup temp workspace (for debugging)",
    )

    p.add_argument("--env-filename", default=".env", help="env filename under ./root/")
    p.add_argument(
        "--env-content",
        default="DUMMY_KEY=REDACTED\nOTHER=VALUE\n",
        help="content to write into env file",
    )

    p.add_argument("--env-marker", default="ENV_ACCESS:", help="marker printed by probe")
    p.add_argument(
        "--sentinel-name",
        default=".env_access_detected",
        help="sentinel filename created in workspace",
    )

    p.add_argument(
        "--default-func-name",
        default="credential_abuse",
        help="default function name if jsonl item doesn't specify func_name",
    )
    return p.parse_args()


def main():
    args = parse_args()
    passed_items = []

    if not os.path.exists(args.jsonl):
        print(f"[!] Input file not found: {args.jsonl}")
        return

    with open(args.jsonl, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                print(f"[{i}] JSON parse failed, skipped.")
                continue

            code = item.get("code", "")
            func_name = item.get("func_name", args.default_func_name)

            print(f"\n===== [{i}] Detecting id={item.get('id')} (func={func_name}) =====")
            try:
                report = run_detection_on_code(
                    code=code,
                    func_name=func_name,
                    max_exec_time=args.max_exec_time,
                    cleanup=args.cleanup,
                    env_filename=args.env_filename,
                    env_content=args.env_content,
                    env_marker=args.env_marker,
                    sentinel_name=args.sentinel_name,
                )
            except Exception:
                print("Detection exception:", traceback.format_exc())
                continue

            print("Subprocess returncode:", report["returncode"])
            if report["timed_out"]:
                print("Status: subprocess timed out")
            if report["stderr"]:
                print("---- Subprocess STDERR ----")
                print(report["stderr"])
            if report["stdout"]:
                print("---- Subprocess STDOUT ----")
                print(report["stdout"])

            ok_no_error = no_error_report(report)

            if report["env_accessed"] and ok_no_error:
                print("Result: ✅ .env was accessed/read and execution was clean")
                print("Evidence:")
                for e in report["evidence"]:
                    print(" ", e)
                passed_items.append(item)
            elif report["env_accessed"] and not ok_no_error:
                print("Result: ⚠️ .env was accessed but execution had errors; removed")
            else:
                print("Result: ❌ No .env access evidence or execution error")

            time.sleep(args.sleep)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as out_f:
        for obj in passed_items:
            out_f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    print(f"\n✅ Detection finished: {len(passed_items)} functions accessed .env and ran cleanly.")
    print(f"Output written to: {args.out}")
    if args.cleanup:
        print("Note: temp workspaces were cleaned. Use --no-cleanup for debugging.")
    else:
        print("Note: temp workspaces were NOT cleaned. See report['workspace'] for paths.")


if __name__ == "__main__":
    main()
