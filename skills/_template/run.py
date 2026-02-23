import os

args = os.environ.get("SKILL_ARGS", "")
print(f"[template] args={args}")
print(f"[template] skill_dir={os.environ.get('SKILL_DIR')}")
