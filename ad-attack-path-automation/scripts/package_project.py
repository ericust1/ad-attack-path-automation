import zipfile
import os
import sys
from pathlib import Path

PROJECT_NAME = "ad-attack-path-automation"


def package_project(output_dir=".", exclude_patterns=None):
    if exclude_patterns is None:
        exclude_patterns = [
            "__pycache__",
            ".pyc",
            ".pyo",
            ".git",
            ".venv",
            "venv",
            "env",
            "neo4j_data",
            "lab_output",
            "reports",
            "*.egg-info",
            ".DS_Store",
        ]

    project_root = Path(__file__).parent.parent
    source_dir = project_root

    output_path = Path(output_dir) / f"{PROJECT_NAME}.zip"

    def should_exclude(file_path):
        rel = os.path.relpath(file_path, source_dir)
        parts = rel.replace("\\", "/").split("/")
        for part in parts:
            for pattern in exclude_patterns:
                if pattern.startswith("*"):
                    if part.endswith(pattern[1:]):
                        return True
                elif part == pattern:
                    return True
        return False

    files_added = 0
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(source_dir):
            dirs[:] = [d for d in dirs if not should_exclude(os.path.join(root, d))]
            for file in files:
                file_path = os.path.join(root, file)
                if should_exclude(file_path):
                    continue
                arcname = os.path.relpath(file_path, source_dir)
                zf.write(file_path, arcname)
                files_added += 1

    print(f"Package created: {output_path}")
    print(f"Files included: {files_added}")
    return str(output_path)


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "."
    package_project(output)
