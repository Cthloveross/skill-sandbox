import argparse
import os
import runpy
from pathlib import Path

def main():
    parser = argparse.ArgumentParser("skills-sandbox")
    parser.add_argument("--skill", required=True, help="Folder name under ./skills")
    parser.add_argument("--entry", default="run.py", help="Entrypoint inside the skill folder")
    parser.add_argument("args", nargs="*", help="Args forwarded to the skill")
    ns = parser.parse_args()

    skill_dir = Path("/workspace/skills") / ns.skill
    entry = skill_dir / ns.entry

    if not skill_dir.exists():
        raise SystemExit(f"Skill not found: {skill_dir}")
    if not entry.exists():
        raise SystemExit(f"Entrypoint not found: {entry}")

    # Simple way to pass args
    os.environ["SKILL_ARGS"] = " ".join(ns.args)
    os.environ["SKILL_DIR"] = str(skill_dir)

    runpy.run_path(str(entry), run_name="__main__")

if __name__ == "__main__":
    main()
