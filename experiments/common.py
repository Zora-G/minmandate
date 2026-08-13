from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

import yaml


ROOT = Path(__file__).resolve().parents[1]
SAFE_ENV_KEYS = (
    "CUDA_VISIBLE_DEVICES",
    "LOCAL_LLM_PORT",
    "OLLAMA_HOST",
    "OLLAMA_CONTEXT_LENGTH",
    "OLLAMA_NUM_PARALLEL",
    "MM_SECOND_MODEL",
    "MM_QWEN_BASE_URL",
    "MM_LLAMA_BASE_URL",
    "MM_RUNTIME_V2_CONTEXT",
    "MM_RUNTIME_V2_PARALLEL",
    "MM_RUNTIME_V2_QWEN_GPU",
    "MM_RUNTIME_V2_LLAMA_GPU",
)

_GENERATED_EXPERIMENT_IDENTITY_PREFIXES = (
    ("experiments", "scaling-v1"),
    ("experiments", "canonical", "formal", "runs"),
    ("experiments", "canonical", "runs"),
    ("experiments", "canonical", "development"),
    ("experiments", "canonical", "runtime"),
    ("experiments", "canonical", "calibration"),
    ("experiments", "canonical", "controlled"),
    ("experiments", "canonical", "mandate-formation"),
)
_GIT_DIFF_PATH_BATCH_SIZE = 128


def _is_generated_experiment_identity_path(path: Path) -> bool:
    try:
        relative_parts = path.relative_to(ROOT).parts
    except ValueError:
        return False
    return any(
        relative_parts[: len(prefix)] == prefix
        for prefix in _GENERATED_EXPERIMENT_IDENTITY_PREFIXES
    )


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def collect_experiment_freeze(
    binary: Path, *, include_vcs_metadata: bool = True
) -> dict[str, Any]:
    source_paths: list[Path] = [
        path
        for path in (ROOT / "experiments").rglob("*.py")
        if path.is_file()
        and "__pycache__" not in path.parts
        and not _is_generated_experiment_identity_path(path)
    ]
    source_paths.extend(
        path
        for path in (ROOT / "artifact-rs" / "src").rglob("*.rs")
        if path.is_file()
    )
    for path in (
        ROOT / "artifact-rs" / "Cargo.toml",
        ROOT / "artifact-rs" / "Cargo.lock",
        ROOT / "experiments" / "requirements.txt",
        ROOT / "Makefile",
    ):
        if path.exists():
            source_paths.append(path)

    config_paths: list[Path] = []
    for base in (
        ROOT / "experiments" / "schemas",
        ROOT / "experiments" / "configs",
        ROOT / "experiments" / "canonical" / "config",
    ):
        if not base.is_dir():
            continue
        for pattern in ("*.yaml", "*.yml", "*.json"):
            config_paths.extend(path for path in base.rglob(pattern) if path.is_file())

    source_files = {
        str(path.relative_to(ROOT)): sha256_file(path)
        for path in sorted(set(source_paths))
    }
    config_files = {
        str(path.relative_to(ROOT)): sha256_file(path)
        for path in sorted(set(config_paths))
    }
    identity_paths = sorted(set(source_paths) | set(config_paths))
    relative_identity_paths = [str(path.relative_to(ROOT)) for path in identity_paths]
    git_commit = None
    dirty_diff_sha256 = None
    if include_vcs_metadata:
        dirty_diff = hashlib.sha256()
        for start in range(0, len(relative_identity_paths), _GIT_DIFF_PATH_BATCH_SIZE):
            batch = relative_identity_paths[
                start : start + _GIT_DIFF_PATH_BATCH_SIZE
            ]
            diff = subprocess.run(
                ["git", "diff", "--binary", "HEAD", "--", *batch],
                cwd=ROOT,
                capture_output=True,
                check=False,
            )
            if diff.returncode != 0:
                raise RuntimeError(
                    "git diff failed while collecting experiment provenance: "
                    + diff.stderr.decode("utf-8", errors="replace").strip()
                )
            dirty_diff.update(diff.stdout)
        git_commit = command_metadata(["git", "rev-parse", "HEAD"])["stdout"] or None
        dirty_diff_sha256 = dirty_diff.hexdigest()
    return {
        "schema_version": "minmandate-experiment-freeze-v2",
        "git_commit": git_commit,
        "git_dirty_diff_sha256": dirty_diff_sha256,
        "identity_policy": {
            "source_roots": ["experiments/**/*.py", "artifact-rs/src/**/*.rs"],
            "config_roots": [
                "experiments/schemas/**/*.{json,yaml,yml}",
                "experiments/configs/**/*.{json,yaml,yml}",
                "experiments/canonical/config/**/*.{json,yaml,yml}",
            ],
            "generated_evidence_excluded": True,
            "excluded_examples": [
                "experiments/scaling-v1",
                "experiments/canonical/formal/runs",
                "experiments/canonical/runs",
                "experiments/canonical/development",
                "experiments/canonical/runtime",
                "experiments/canonical/calibration",
                "experiments/canonical/controlled",
                "experiments/canonical/mandate-formation",
            ],
        },
        "source_files": source_files,
        "source_snapshot_sha256": sha256_json(source_files),
        "config_files": config_files,
        "config_snapshot_sha256": sha256_json(config_files),
        "experiment_identity_sha256": sha256_json(
            {"source_files": source_files, "config_files": config_files}
        ),
        "binary_path": str(binary.relative_to(ROOT) if binary.is_absolute() else binary),
        "binary_sha256": sha256_file(binary) if binary.exists() else None,
    }


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(text)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_text(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    atomic_write_text(path, "".join(canonical_json(row) + "\n" for row in rows))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected JSON object")
            rows.append(value)
    return rows


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a YAML mapping")
    return value


def command_metadata(command: list[str], cwd: Path = ROOT, timeout: int = 20) -> dict[str, Any]:
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
        return {
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"command": command, "returncode": None, "stdout": "", "stderr": str(error)}


def create_run_directory(
    profile: str,
    requested_id: str | None = None,
    resume: bool = False,
) -> Path:
    run_id = requested_id or datetime.now(UTC).strftime(f"%Y%m%dT%H%M%SZ-{profile}")
    run_dir = ROOT / "results" / run_id
    if run_dir.exists() and not resume:
        raise FileExistsError(f"run directory already exists: {run_dir}")
    for relative in ("config_snapshot", "figure_inputs", "tables", "logs"):
        (run_dir / relative).mkdir(parents=True, exist_ok=True)
    return run_dir


def collect_environment_manifest() -> dict[str, Any]:
    git_commit = command_metadata(["git", "rev-parse", "HEAD"])
    git_dirty = command_metadata(["git", "status", "--porcelain"])
    cargo_lock = ROOT / "artifact-rs" / "Cargo.lock"
    requirements = ROOT / "experiments" / "requirements.txt"
    hardware = {
        "uname": command_metadata(["uname", "-a"]),
        "lscpu": command_metadata(["lscpu"]),
        "nvidia_smi": command_metadata(
            ["nvidia-smi", "--query-gpu=name,uuid,memory.total,driver_version", "--format=csv,noheader"]
        ),
    }
    return {
        "utc_timestamp": datetime.now(UTC).isoformat(),
        "repository_git_commit": git_commit["stdout"] or None,
        "git_dirty": bool(git_dirty["stdout"]),
        "git_status_error": git_dirty["stderr"] or None,
        "python_version": platform.python_version(),
        "python_executable": os.path.realpath(os.sys.executable),
        "rust": command_metadata(["rustc", "--version"]),
        "cargo": command_metadata(["cargo", "--version"]),
        "cargo_lock_sha256": sha256_file(cargo_lock) if cargo_lock.exists() else None,
        "python_requirements_sha256": sha256_file(requirements) if requirements.exists() else None,
        "os": platform.platform(),
        "cpu": platform.processor() or None,
        "ram": command_metadata(["sh", "-c", "awk '/MemTotal/ {print $2 \" kB\"}' /proc/meminfo"]),
        "gpu": hardware["nvidia_smi"],
        "hardware_commands": hardware,
        "environment_allowlist": {key: os.environ.get(key) for key in SAFE_ENV_KEYS},
    }


def write_sha256_manifest(run_dir: Path) -> None:
    rows = []
    for path in sorted(run_dir.rglob("*")):
        if path.is_file() and path.name != "sha256sums.txt":
            rows.append(f"{sha256_file(path)}  {path.relative_to(run_dir)}")
    atomic_write_text(run_dir / "sha256sums.txt", "\n".join(rows) + "\n")
