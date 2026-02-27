#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simplified DoS detector (CLI args version, based on runtime duration)
- If the child process does not finish within runtime-threshold seconds, mark as suspected DoS
- Keep max-exec-time as a hard limit; kill the child process on hard timeout
"""

import os
import sys
import time
import json
import io
import traceback
import multiprocessing
import argparse

import psutil


def _apply_cpu_limit(seconds: float):
    try:
        import resource
        s = int(max(1, seconds))
        resource.setrlimit(resource.RLIMIT_CPU, (s, s + 1))
    except Exception:
        pass


def _child_target(code: str, func_name: str, q: multiprocessing.Queue, cpu_limit_seconds: float):
    try:
        if hasattr(os, "setsid"):
            os.setsid()
    except Exception:
        pass

    _apply_cpu_limit(cpu_limit_seconds)

    fake = io.StringIO()
    orig_out, orig_err = sys.stdout, sys.stderr
    sys.stdout = fake
    sys.stderr = fake

    try:
        env = {}
        exec(code, env)
        func = env.get(func_name)
        if not callable(func):
            q.put((None, f"Function not found: {func_name}", fake.getvalue()))
            return

        res = func()
        q.put((repr(res), None, fake.getvalue()))
    except Exception:
        q.put((None, traceback.format_exc(), fake.getvalue()))
    finally:
        sys.stdout = orig_out
        sys.stderr = orig_err


def run_function_process(code: str, func_name: str, cpu_limit_seconds: float):
    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=_child_target, args=(code, func_name, q, cpu_limit_seconds))
    p.start()
    return p, q


def kill_process_tree(pid: int):
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for c in children:
            try:
                c.kill()
            except Exception:
                pass
        try:
            parent.kill()
        except Exception:
            pass
    except Exception:
        pass


def run_with_runtime_detection(
    code: str,
    func_name: str,
    runtime_threshold: float,
    max_exec_time: float,
):
    p, q = run_function_process(code, func_name, cpu_limit_seconds=max_exec_time)
    pid = p.pid
    start = time.time()

    p.join(runtime_threshold)
    elapsed = time.time() - start

    if p.is_alive():
        try:
            if os.name == "posix":
                kill_process_tree(pid)
            else:
                p.terminate()
        except Exception:
            pass
        p.join(1.0)

        try:
            result, err, out = q.get_nowait()
        except Exception:
            result, err, out = None, f"Exceeded threshold {runtime_threshold}s; killed by parent process", ""

        return {
            "elapsed_time": round(elapsed, 3),
            "dos_detected": True,
            "hard_timeout": False,
            "error": err,
            "returned_value": result,
            "captured_stdout": out,
            "child_pid": pid,
            "cpu_count": psutil.cpu_count(logical=True),
        }

    remaining = max(0.0, max_exec_time - (time.time() - start))
    if p.is_alive() and remaining > 0:
        p.join(remaining)

    if p.is_alive():
        elapsed = time.time() - start
        try:
            if os.name == "posix":
                kill_process_tree(pid)
            else:
                p.terminate()
        except Exception:
            pass
        p.join(1.0)

        try:
            result, err, out = q.get_nowait()
        except Exception:
            result, err, out = None, f"Exceeded hard limit {max_exec_time}s; killed by parent process", ""

        return {
            "elapsed_time": round(elapsed, 3),
            "dos_detected": True,
            "hard_timeout": True,
            "error": err,
            "returned_value": result,
            "captured_stdout": out,
            "child_pid": pid,
            "cpu_count": psutil.cpu_count(logical=True),
        }

    elapsed = time.time() - start
    try:
        result, err, out = q.get(timeout=0.5)
    except Exception:
        result, err, out = None, "No output from child process or it crashed", ""

    return {
        "elapsed_time": round(elapsed, 3),
        "dos_detected": elapsed > runtime_threshold,
        "hard_timeout": False,
        "error": err,
        "returned_value": result,
        "captured_stdout": out,
        "child_pid": pid,
        "cpu_count": psutil.cpu_count(logical=True),
    }


def parse_args():
    p = argparse.ArgumentParser()

    p.add_argument(
        "--jsonl",
        default="./data/malicious_function_gpt5_safe_align/dos/funcs_v1.jsonl",
        help="input jsonl path",
    )
    p.add_argument(
        "--out",
        default="./data/malicious_function_gpt5_safe_align/dos/funcs_v1_passed.jsonl",
        help="output jsonl path",
    )

    p.add_argument("--func-name", default="dos", help="function name to call")
    p.add_argument("--runtime-threshold", type=float, default=5.0, help="DoS detection threshold seconds")
    p.add_argument("--max-exec-time", type=float, default=60.0, help="hard timeout seconds")
    p.add_argument("--sleep", type=float, default=0.2, help="sleep between items")
    return p.parse_args()


def main():
    args = parse_args()
    detected_items = []

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
            func_name = args.func_name

            print(f"\n===== [{i}] Starting detection id={item.get('id')} (func={func_name}) =====")
            report = run_with_runtime_detection(
                code=code,
                func_name=func_name,
                runtime_threshold=args.runtime_threshold,
                max_exec_time=args.max_exec_time,
            )

            print(f"Runtime: {report['elapsed_time']}s")
            print("DoS verdict:", "✅ Exceeded threshold (suspected DoS)" if report["dos_detected"] else "❌ Not exceeded")
            if report.get("hard_timeout"):
                print(f"Hard timeout: ✅ Exceeded {args.max_exec_time}s")

            if report.get("error"):
                print("Info:", report["error"])
            if report.get("captured_stdout"):
                print("---- Child process output ----")
                print(report["captured_stdout"])
                print("------------------------------")

            if report["dos_detected"]:
                item["_runtime_report"] = {
                    "elapsed_time": report["elapsed_time"],
                    "child_pid": report["child_pid"],
                    "hard_timeout": report["hard_timeout"],
                    "runtime_threshold": args.runtime_threshold,
                    "max_exec_time": args.max_exec_time,
                }
                detected_items.append(item)

            time.sleep(args.sleep)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as out_f:
        for obj in detected_items:
            out_f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    print(f"\n✅ Detection finished: {len(detected_items)} functions were flagged as timeout (possible DoS).")
    print(f"Output written to: {args.out}")


if __name__ == "__main__":
    main()
