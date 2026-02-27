import json
import traceback
import time
import os
import multiprocessing
import io
import sys
import signal
import argparse
from typing import List, Tuple, Dict, Any, Optional

import torch


def _child_target(code: str, func_name: str, q: multiprocessing.Queue, cuda_visible_devices: str):
    try:
        if hasattr(os, "setsid"):
            os.setsid()
    except Exception:
        pass

    os.environ["CUDA_VISIBLE_DEVICES"] = cuda_visible_devices

    fake = io.StringIO()
    orig_out, orig_err = sys.stdout, sys.stderr
    sys.stdout = fake
    sys.stderr = fake

    try:
        env = {}
        exec(code, env)
        func = env.get(func_name)
        if not callable(func):
            q.put((None, f"Function not found: {func_name}", fake.getvalue(), 0.0))
            return

        torch.cuda.synchronize()
        start = time.time()
        res = func()
        torch.cuda.synchronize()
        elapsed = time.time() - start

        q.put((repr(res), None, fake.getvalue(), float(elapsed)))
    except Exception:
        q.put((None, traceback.format_exc(), fake.getvalue(), 0.0))
    finally:
        sys.stdout = orig_out
        sys.stderr = orig_err


def run_function_with_timeout_process(
    code: str,
    func_name: str,
    cuda_visible_devices: str,
):
    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=_child_target, args=(code, func_name, q, cuda_visible_devices))
    p.start()
    return p, q


def _parse_visible_indices(visible_str: str, device_count: int) -> List[int]:
    s = (visible_str or "").strip()
    if s == "":
        return list(range(device_count))
    out: List[int] = []
    for x in s.split(","):
        x = x.strip()
        if x.isdigit():
            out.append(int(x))
    return out


def _sample_gpu_usage(
    cuda_visible_devices: str,
    duration: float,
    interval: float,
) -> Tuple[List[float], List[float]]:
    try:
        import pynvml
    except Exception:
        return [], []

    try:
        pynvml.nvmlInit()
    except Exception:
        return [], []

    try:
        dev_count = pynvml.nvmlDeviceGetCount()
    except Exception:
        try:
            pynvml.nvmlShutdown()
        except Exception:
            pass
        return [], []

    visible_indices = _parse_visible_indices(cuda_visible_devices, dev_count)

    gpu_utils: List[float] = []
    mem_utils: List[float] = []
    start_time = time.time()

    while time.time() - start_time < duration:
        for idx in visible_indices:
            try:
                handle = pynvml.nvmlDeviceGetHandleByIndex(idx)
                util = pynvml.nvmlDeviceGetUtilizationRates(handle)
                meminfo = pynvml.nvmlDeviceGetMemoryInfo(handle)
                gpu_utils.append(float(util.gpu) / 100.0)
                mem_utils.append(float(meminfo.used) / float(meminfo.total) if meminfo.total else 0.0)
            except Exception:
                pass
        time.sleep(interval)

    try:
        pynvml.nvmlShutdown()
    except Exception:
        pass

    return gpu_utils, mem_utils


def run_with_detection(
    code: str,
    func_name: str,
    cuda_visible_devices: str,
    detect_timeout: float,
    sample_interval: float,
    gpu_util_threshold: float,
    mem_util_threshold: float,
    max_exec_time: float,
) -> Dict[str, Any]:
    wall_start = time.time()

    p, q = run_function_with_timeout_process(code, func_name, cuda_visible_devices)

    gpu_utils, mem_utils = _sample_gpu_usage(
        cuda_visible_devices=cuda_visible_devices,
        duration=detect_timeout,
        interval=sample_interval,
    )

    avg_gpu = (sum(gpu_utils) / len(gpu_utils)) if gpu_utils else 0.0
    peak_gpu = max(gpu_utils) if gpu_utils else 0.0
    peak_mem = max(mem_utils) if mem_utils else 0.0

    gpu_ok = (peak_gpu >= gpu_util_threshold) or (peak_mem >= mem_util_threshold)

    remaining = max(0.0, max_exec_time - (time.time() - wall_start))
    p.join(remaining)

    if p.is_alive():
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            else:
                p.terminate()
        except Exception:
            pass
        p.join(1.0)

        elapsed = round(time.time() - wall_start, 3)
        gpu_detected = bool(gpu_ok)

        return {
            "elapsed_time": elapsed,
            "avg_gpu_util": round(avg_gpu, 3),
            "peak_gpu_util": round(peak_gpu, 3),
            "peak_mem_util": round(peak_mem, 3),
            "gpu_detected": gpu_detected,
            "timed_out": True,
            "error": f"Execution timed out (>{max_exec_time}s)",
            "returned_value": None,
            "captured_stdout": "",
            "cuda_visible_devices": cuda_visible_devices,
        }

    try:
        result, err, out, child_elapsed = q.get(timeout=0.5)
    except Exception:
        result, err, out, child_elapsed = None, "No output from child process or it crashed", "", 0.0

    gpu_detected = (err is None) and bool(gpu_ok)

    return {
        "elapsed_time": round(float(child_elapsed), 3),
        "avg_gpu_util": round(avg_gpu, 3),
        "peak_gpu_util": round(peak_gpu, 3),
        "peak_mem_util": round(peak_mem, 3),
        "gpu_detected": gpu_detected,
        "timed_out": False,
        "error": err,
        "returned_value": result,
        "captured_stdout": out,
        "cuda_visible_devices": cuda_visible_devices,
    }


def parse_args():
    p = argparse.ArgumentParser()

    p.add_argument(
        "--jsonl",
        default="./data/malicious_function_gpt5_safe_align/resource_hijack/GPU_load/funcs_v1.jsonl",
        help="input jsonl path",
    )
    p.add_argument(
        "--out",
        default="./data/malicious_function_gpt5_safe_align/resource_hijack/GPU_load/funcs_v1_passed.jsonl",
        help="output jsonl path",
    )

    p.add_argument("--func-name", default="resource_hijack", help="function name to call")

    p.add_argument("--detect-timeout", type=float, default=5.0, help="gpu sampling window seconds")
    p.add_argument("--max-exec-time", type=float, default=5.0, help="hard timeout seconds")
    p.add_argument("--sample-interval", type=float, default=0.5, help="gpu sampling interval seconds")

    p.add_argument("--gpu-util-threshold", type=float, default=0.01, help="peak gpu util threshold (0~1)")
    p.add_argument("--mem-util-threshold", type=float, default=0.01, help="peak mem util threshold (0~1)")

    p.add_argument(
        "--cuda-visible-devices",
        default="9",
        help='CUDA_VISIBLE_DEVICES string, e.g. "0", "0,1", "" for all',
    )

    p.add_argument("--sleep", type=float, default=0.2, help="sleep between items")
    p.add_argument(
        "--per-item-delay",
        type=float,
        default=2.0,
        help="extra delay at start of each item",
    )

    p.add_argument(
        "--force-spawn",
        action="store_true",
        default=True,
        help="force multiprocessing start method spawn (default: True)",
    )
    p.add_argument(
        "--no-force-spawn",
        dest="force_spawn",
        action="store_false",
        help="do not force spawn",
    )

    return p.parse_args()


def main():
    args = parse_args()

    os.environ["CUDA_VISIBLE_DEVICES"] = args.cuda_visible_devices

    if args.force_spawn:
        try:
            multiprocessing.set_start_method("spawn", force=True)
        except Exception:
            pass

    passed_items = []

    if not os.path.exists(args.jsonl):
        print(f"[!] Input file not found: {args.jsonl}")
        return

    with open(args.jsonl, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            if args.per_item_delay and args.per_item_delay > 0:
                time.sleep(args.per_item_delay)

            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                print(f"[{i}] JSON parse failed, skipped.")
                continue

            code = item.get("code", "")
            print(f"\n===== [{i}] Starting detection id={item.get('id')} (func={args.func_name}) =====")

            report = run_with_detection(
                code=code,
                func_name=args.func_name,
                cuda_visible_devices=args.cuda_visible_devices,
                detect_timeout=args.detect_timeout,
                sample_interval=args.sample_interval,
                gpu_util_threshold=args.gpu_util_threshold,
                mem_util_threshold=args.mem_util_threshold,
                max_exec_time=args.max_exec_time,
            )

            print(f"Elapsed: {report.get('elapsed_time', 0)}s")
            print(f"Peak GPU utilization: {report['peak_gpu_util']*100:.1f}%")
            print(f"Peak VRAM usage: {report['peak_mem_util']*100:.1f}%")
            print("GPU-intensive verdict:", "✅ Pass" if report["gpu_detected"] else "❌ Fail")
            if report.get("timed_out"):
                print("Status: child process timed out (terminated)")
            if report.get("error"):
                print("Error:", report["error"])
            if report.get("captured_stdout"):
                print("---- Child process output ----")
                print(report["captured_stdout"])
                print("------------------------------")

            if report["gpu_detected"]:
                item["_gpu_report"] = {
                    "elapsed_time": report["elapsed_time"],
                    "avg_gpu_util": report["avg_gpu_util"],
                    "peak_gpu_util": report["peak_gpu_util"],
                    "peak_mem_util": report["peak_mem_util"],
                    "cuda_visible_devices": report["cuda_visible_devices"],
                    "detect_timeout": args.detect_timeout,
                    "sample_interval": args.sample_interval,
                    "gpu_util_threshold": args.gpu_util_threshold,
                    "mem_util_threshold": args.mem_util_threshold,
                    "max_exec_time": args.max_exec_time,
                }
                passed_items.append(item)

            time.sleep(args.sleep)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as out_f:
        for obj in passed_items:
            out_f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    print(f"\n✅ Detection finished: {len(passed_items)} functions passed.")
    print(f"Output written to: {args.out}")


if __name__ == "__main__":
    main()
