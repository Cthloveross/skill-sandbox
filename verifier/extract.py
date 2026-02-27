#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract.py – AST-based function extractor for skill Python files.

Walks a skill directory, parses every .py file, and emits one JSONL
record per top-level function found.  Each record contains:

    {"id": "<skill>/<file>::<func>", "code": "<full file source>", "func_name": "<func>"}

This JSONL is the universal input format consumed by every verifier
test_func_*.py script.
"""

import ast
import json
import os
import sys
import argparse
from typing import List, Dict


def extract_functions_from_file(filepath: str) -> List[str]:
    """Return names of all top-level function definitions in a Python file."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
        tree = ast.parse(source, filename=filepath)
    except (SyntaxError, ValueError):
        return []

    return [
        node.name
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def extract_from_skill(skill_dir: str, skill_name: str = "") -> List[Dict]:
    """Walk *skill_dir*, return JSONL-ready dicts for every function found."""
    if not skill_name:
        skill_name = os.path.basename(os.path.normpath(skill_dir))

    records: List[Dict] = []

    for root, _dirs, files in os.walk(skill_dir):
        for fname in sorted(files):
            if not fname.endswith(".py"):
                continue
            filepath = os.path.join(root, fname)
            relpath = os.path.relpath(filepath, skill_dir)

            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    code = f.read()
            except Exception:
                continue

            funcs = extract_functions_from_file(filepath)
            if not funcs:
                continue

            for fn in funcs:
                records.append(
                    {
                        "id": f"{skill_name}/{relpath}::{fn}",
                        "code": code,
                        "func_name": fn,
                        "skill": skill_name,
                        "file": relpath,
                    }
                )

    return records


def main():
    p = argparse.ArgumentParser(
        description="Extract top-level functions from skill .py files → JSONL"
    )
    p.add_argument("skill_dir", help="Path to a skill directory (e.g. skills/docx-to-pdf)")
    p.add_argument(
        "--out",
        default=None,
        help="Output JSONL path (default: stdout)",
    )
    args = p.parse_args()

    if not os.path.isdir(args.skill_dir):
        print(f"[!] Not a directory: {args.skill_dir}", file=sys.stderr)
        sys.exit(1)

    records = extract_from_skill(args.skill_dir)

    if not records:
        print(f"[!] No functions found in {args.skill_dir}", file=sys.stderr)
        sys.exit(0)

    out_f = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    try:
        for rec in records:
            out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    finally:
        if args.out:
            out_f.close()

    print(
        f"[✓] Extracted {len(records)} functions from {args.skill_dir}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
