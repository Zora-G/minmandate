#!/usr/bin/env python3
"""Build and score the MinMandate + Stable Handle intent-recovery ablation.

The construction path reads only public observer artifacts.  In particular, it
does not read workflow IDs, task labels, or gold workflow groupings.  A
separate validation path may read private truth only after the attack prompts
have been frozen.
"""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import re
import secrets
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


HANDLE_FIELD = "raw_capability_handle"
HANDLE_RE = re.compile(r"^[0-9a-f]{32}$")
AP2_PROFILE = "ap2_official"
MINMANDATE_PROFILE = "full_minmandate"
ASSEMBLY_METHOD = "deterministic_exact_stable_handle_v1"
SEMANTIC_EQUIVALENCE_STANDARD = (
    "Mark intent_semantically_equivalent=true only when the reconstruction "
    "recovers the same high-level objective or decision, the same target or "
    "decision object, and the same direction of action as the original user "
    "intent. Exact wording and operational substeps need not match. A list of "
    "merchant calls without the global objective is false. Unsupported "
    "additions that materially change the decision are false."
)
ATTACK_SCHEMA = {
    "type": "object",
    "properties": {"reconstructed_intent": {"type": "string", "minLength": 1}},
    "required": ["reconstructed_intent"],
    "additionalProperties": False,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(_canonical(row) + "\n")


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _new_output_dir(path: Path) -> None:
    if path.exists() and any(path.iterdir()):
        raise ValueError(f"refusing to overwrite non-empty output directory: {path}")
    path.mkdir(parents=True, exist_ok=True)


def _record_call_ids(records: list[dict[str, Any]]) -> list[str]:
    ids = [str(record["call_id"]) for record in records]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate call_id in observer records")
    return ids


def _source_prompt_contract(
    prompt_rows: list[dict[str, Any]],
) -> tuple[str, dict[str, Any]]:
    systems = {row["prompt"]["system"] for row in prompt_rows}
    schemas = {
        _canonical(row["prompt"]["input"]["output_schema"]) for row in prompt_rows
    }
    if len(systems) != 1 or len(schemas) != 1:
        raise ValueError("source campaign does not have one frozen prompt contract")
    return next(iter(systems)), json.loads(next(iter(schemas)))


def _public_ap2_clusters(
    assembly_rows: list[dict[str, Any]],
) -> dict[str, list[list[str]]]:
    """Return public exact-value AP2 clusters, without opening private truth."""
    by_pool: dict[str, list[list[str]]] = {}
    for row in assembly_rows:
        if row["profile"] != AP2_PROFILE:
            continue
        if row.get("assembly_method") != "deterministic_exact_value_reuse_audit_v1":
            raise ValueError("unexpected public AP2 assembly method")
        pool_id = str(row["pool_id"])
        clusters = [
            sorted(str(call_id) for call_id in cluster)
            for cluster in row["prediction"]["clusters"]
        ]
        if pool_id in by_pool:
            raise ValueError(f"duplicate AP2 assembly row for {pool_id}")
        by_pool[pool_id] = sorted(clusters)
    if not by_pool:
        raise ValueError("no public AP2 exact-value clusters found")
    return by_pool


def _source_views(
    pool_rows: list[dict[str, Any]],
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    views: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in pool_rows:
        key = (str(row["pool_id"]), str(row["profile"]))
        if key in views:
            raise ValueError(f"duplicate public pool view: {key}")
        views[key] = row["records"]
    return views


def _attack_id(pool_id: str, call_ids: list[str]) -> str:
    # The identifier is outside the model-visible prompt.  It is derived only
    # from public opaque call IDs so that later scoring can join artifacts.
    material = "stable-handle-ablation-v1|" + pool_id + "|" + "|".join(call_ids)
    return "intent_sh_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def build(args: argparse.Namespace) -> None:
    campaign = args.campaign.resolve()
    output = args.output.resolve()
    _new_output_dir(output)

    pool_path = campaign / "protocol_pool_views.jsonl"
    assembly_path = campaign / "deterministic_exact_value_assembly_predictions.jsonl"
    prompts_path = campaign / "intent_attack_prompts.jsonl"
    for path in (pool_path, assembly_path, prompts_path):
        if not path.is_file():
            raise FileNotFoundError(path)

    pool_rows = _read_jsonl(pool_path)
    assembly_rows = _read_jsonl(assembly_path)
    source_prompt_rows = _read_jsonl(prompts_path)
    system_prompt, output_schema = _source_prompt_contract(source_prompt_rows)
    views = _source_views(pool_rows)
    clusters_by_pool = _public_ap2_clusters(assembly_rows)

    instrumented_rows: list[dict[str, Any]] = []
    assembly_predictions: list[dict[str, Any]] = []
    attack_prompts: list[dict[str, Any]] = []
    public_attack_map: list[dict[str, Any]] = []
    handle_commitments: list[dict[str, Any]] = []
    all_handles: set[str] = set()
    source_mm_by_call: dict[str, dict[str, Any]] = {}

    expected_pool_ids = sorted(clusters_by_pool)
    workflow_count = sum(len(clusters_by_pool[p]) for p in expected_pool_ids)
    if workflow_count != args.expected_workflows:
        raise ValueError(
            f"expected {args.expected_workflows} public workflow clusters, "
            f"found {workflow_count}"
        )

    for pool_id in expected_pool_ids:
        ap2_records = views[(pool_id, AP2_PROFILE)]
        mm_records = views[(pool_id, MINMANDATE_PROFILE)]
        ap2_ids = set(_record_call_ids(ap2_records))
        mm_ids = set(_record_call_ids(mm_records))
        if ap2_ids != mm_ids:
            raise ValueError(f"AP2 and MinMandate call sets differ in {pool_id}")

        flattened = [
            call_id
            for cluster in clusters_by_pool[pool_id]
            for call_id in cluster
        ]
        if len(flattened) != len(set(flattened)) or set(flattened) != mm_ids:
            raise ValueError(f"public AP2 clusters are not a partition in {pool_id}")

        call_to_handle: dict[str, str] = {}
        for cluster in clusters_by_pool[pool_id]:
            handle = secrets.token_hex(16)
            while handle in all_handles:
                handle = secrets.token_hex(16)
            if not HANDLE_RE.fullmatch(handle):
                raise AssertionError("generated handle is not 128-bit lowercase hex")
            all_handles.add(handle)
            for call_id in cluster:
                call_to_handle[call_id] = handle
            handle_commitments.append(
                {
                    "pool_id": pool_id,
                    "call_ids": cluster,
                    "handle_sha256": _sha256_bytes(handle.encode("ascii")),
                }
            )

        instrumented_records: list[dict[str, Any]] = []
        for source_record in mm_records:
            call_id = str(source_record["call_id"])
            source_mm_by_call[call_id] = copy.deepcopy(source_record)
            record = copy.deepcopy(source_record)
            wire = record.get("protocol_wire")
            if not isinstance(wire, dict):
                raise ValueError(f"protocol_wire is not an object for {call_id}")
            if HANDLE_FIELD in wire:
                raise ValueError(f"source wire already contains {HANDLE_FIELD}")
            wire[HANDLE_FIELD] = call_to_handle[call_id]
            instrumented_records.append(record)

        instrumented_rows.append(
            {
                "pool_id": pool_id,
                "profile": "full_minmandate_stable_handle",
                "records": instrumented_records,
            }
        )

        # This is the only assembly rule in the ablation.  It sees the
        # instrumented merchant records and exact handle equality, never private
        # workflow IDs or gold groups.
        handle_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in instrumented_records:
            handle = record["protocol_wire"][HANDLE_FIELD]
            handle_groups[handle].append(record)

        clusters = sorted(
            [sorted(str(r["call_id"]) for r in group) for group in handle_groups.values()]
        )
        assembly_predictions.append(
            {
                "assembly_method": ASSEMBLY_METHOD,
                "kind": "assembly",
                "pool_id": pool_id,
                "prediction": {"clusters": clusters, "pool_id": pool_id},
                "profile": "full_minmandate_stable_handle",
                "query_id": pool_id,
            }
        )

        for handle in sorted(handle_groups):
            stripped_records: list[dict[str, Any]] = []
            for instrumented in sorted(
                handle_groups[handle], key=lambda row: str(row["call_id"])
            ):
                stripped = copy.deepcopy(instrumented)
                del stripped["protocol_wire"][HANDLE_FIELD]
                call_id = str(stripped["call_id"])
                if _canonical(stripped) != _canonical(source_mm_by_call[call_id]):
                    raise AssertionError("stripping the handle changed a MinMandate record")
                stripped_records.append(stripped)

            call_ids = [str(record["call_id"]) for record in stripped_records]
            attack_id = _attack_id(pool_id, call_ids)
            prompt = {
                "system": system_prompt,
                "input": {
                    "merchant_visible_records": stripped_records,
                    "output_schema": output_schema,
                },
            }
            prompt_text = _canonical(prompt)
            if HANDLE_FIELD in prompt_text or handle in prompt_text:
                raise AssertionError("stable handle leaked into semantic attack input")
            attack_prompts.append({"attack_id": attack_id, "prompt": prompt})
            public_attack_map.append(
                {
                    "attack_id": attack_id,
                    "call_ids": call_ids,
                    "pool_id": pool_id,
                }
            )

    attack_prompts.sort(key=lambda row: row["attack_id"])
    public_attack_map.sort(key=lambda row: row["attack_id"])
    handle_commitments.sort(key=lambda row: (row["pool_id"], row["call_ids"]))

    if len(all_handles) != args.expected_workflows:
        raise AssertionError("handles are not unique across workflows")
    if len(attack_prompts) != args.expected_workflows:
        raise AssertionError("one semantic attack prompt was not built per handle")

    output_files = {
        "instrumented_protocol_pool_views.jsonl": instrumented_rows,
        "stable_handle_assembly_predictions.jsonl": assembly_predictions,
        "intent_attack_prompts.jsonl": attack_prompts,
        "public_attack_map.jsonl": public_attack_map,
        "handle_commitments.jsonl": handle_commitments,
    }
    for name, rows in output_files.items():
        _write_jsonl(output / name, rows)

    record_count = sum(len(row["records"]) for row in instrumented_rows)
    manifest = {
        "schema_version": "minmandate-stable-handle-ablation-v1",
        "run_id": args.run_id,
        "condition": "minmandate_stable_handle_joined",
        "source_campaign": str(campaign),
        "source_artifacts": {
            pool_path.name: _sha256_file(pool_path),
            assembly_path.name: _sha256_file(assembly_path),
            prompts_path.name: _sha256_file(prompts_path),
        },
        "construction": {
            "handle_field": HANDLE_FIELD,
            "handle_bits": 128,
            "handle_encoding": "32 lowercase hexadecimal characters",
            "handle_generator": "Python secrets.token_hex(16) backed by the OS CSPRNG",
            "same_handle_reused_across_merchants_within_public_workflow_cluster": True,
            "handles_independent_across_public_workflow_clusters": True,
            "semantic_payload_encoded": False,
            "assembly_rule": "exact equality on raw_capability_handle",
            "handle_removed_before_semantic_attack": True,
            "public_cluster_source": (
                "AP2 public stable-field exact-value clusters from the frozen "
                "observer artifact; used only to inject one fresh handle into "
                "the call-matched MinMandate replay"
            ),
            "workflow_id_read": False,
            "gold_grouping_read": False,
            "private_truth_read": False,
        },
        "frozen_attack_contract": {
            "source_system_prompt_sha256": _sha256_bytes(system_prompt.encode("utf-8")),
            "source_output_schema": output_schema,
            "semantic_records_equal_source_minmandate_records_after_strip": True,
        },
        "counts": {
            "pools": len(expected_pool_ids),
            "workflows": args.expected_workflows,
            "unique_handles": len(all_handles),
            "merchant_records": record_count,
            "semantic_attack_prompts": len(attack_prompts),
        },
    }
    manifest["outputs_sha256"] = {
        name: _sha256_file(output / name) for name in sorted(output_files)
    }
    _write_json(output / "construction_manifest.json", manifest)


def validate_private(args: argparse.Namespace) -> None:
    campaign = args.campaign.resolve()
    output = args.output.resolve()
    public_map_path = output / "public_attack_map.jsonl"
    if not public_map_path.is_file():
        raise FileNotFoundError(public_map_path)

    public_rows = _read_jsonl(public_map_path)
    truth_rows = _read_jsonl(campaign / "private_pool_truth.jsonl")
    gold_rows = _read_jsonl(campaign / "private_outcome_gold.jsonl")
    gold_by_task = {
        str(row["base_task_id"]): str(row["original_user_intent"]) for row in gold_rows
    }
    truth_by_partition = {
        (str(row["pool_id"]), tuple(sorted(str(x) for x in row["call_ids"]))): row
        for row in truth_rows
    }

    private_score_map: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for row in public_rows:
        key = (str(row["pool_id"]), tuple(sorted(str(x) for x in row["call_ids"])))
        truth = truth_by_partition.get(key)
        if truth is None:
            missing.append(row)
            continue
        task_id = str(truth["base_task_id"])
        private_score_map.append(
            {
                "attack_id": row["attack_id"],
                "base_task_id": task_id,
                "original_user_intent": gold_by_task[task_id],
                "pool_id": row["pool_id"],
                "workflow_id": truth["workflow_id"],
            }
        )

    exact = not missing and len(private_score_map) == len(truth_rows)
    if not exact:
        raise ValueError("stable-handle assembly does not match private truth exactly")
    private_score_map.sort(key=lambda row: row["attack_id"])
    _write_jsonl(output / "private_score_map.jsonl", private_score_map)
    _write_json(
        output / "private_validation.json",
        {
            "schema_version": "minmandate-stable-handle-private-validation-v1",
            "assembly_exact": 1.0,
            "false_joins": 0,
            "missed_workflows": 0,
            "validated_workflows": len(private_score_map),
            "validation_boundary": (
                "Private truth was opened only after public construction and "
                "prompt freezing; it did not affect handle injection, assembly, "
                "record ordering, or semantic attack input."
            ),
            "private_score_map_sha256": _sha256_file(
                output / "private_score_map.jsonl"
            ),
        },
    )


def audit_runtime(args: argparse.Namespace) -> None:
    output = args.output.resolve()
    prompt_rows = _read_jsonl(output / "intent_attack_prompts.jsonl")
    prompt_by_id = {str(row["attack_id"]): row["prompt"] for row in prompt_rows}
    prediction_rows: list[dict[str, Any]] = []
    attempt_rows: list[dict[str, Any]] = []
    for path in args.predictions:
        prediction_rows.extend(_read_jsonl(path.resolve()))
    for path in args.attempts:
        attempt_rows.extend(_read_jsonl(path.resolve()))

    expected_ids = set(prompt_by_id)
    prediction_ids = [str(row["attack_id"]) for row in prediction_rows]
    attempt_ids = [str(row["attack_id"]) for row in attempt_rows]
    if (
        set(prediction_ids) != expected_ids
        or set(attempt_ids) != expected_ids
        or len(prediction_ids) != len(set(prediction_ids))
        or len(attempt_ids) != len(set(attempt_ids))
    ):
        raise ValueError("runtime artifacts do not cover every frozen prompt exactly once")

    options = {
        "temperature": args.temperature,
        "top_p": args.top_p,
        "seed": args.seed,
        "num_ctx": args.num_ctx,
        "num_predict": args.num_predict,
    }
    request_bytes: list[int] = []
    prompt_eval_counts: list[int] = []
    eval_counts: list[int] = []
    request_hashes: set[str] = set()
    first_pass_valid = 0
    stop_reasons: dict[str, int] = defaultdict(int)
    for row in attempt_rows:
        attack_id = str(row["attack_id"])
        if row.get("run_id") != args.run_id or row.get("status") != "valid_prediction":
            raise ValueError(f"invalid run or failed prediction for {attack_id}")
        attempts = row.get("attempts")
        if not isinstance(attempts, list) or len(attempts) != 1:
            raise ValueError(f"{attack_id} did not finish in exactly one attempt")
        attempt = attempts[0]
        if attempt.get("stage") != "initial" or attempt.get("status") != "valid_prediction":
            raise ValueError(f"{attack_id} required a format repair")
        if not row["format_audit"].get("first_pass_valid"):
            raise ValueError(f"{attack_id} is not first-pass schema valid")
        first_pass_valid += 1

        prompt = prompt_by_id[attack_id]
        payload = {
            "model": args.model,
            "messages": [
                {"role": "system", "content": prompt["system"]},
                {
                    "role": "user",
                    "content": json.dumps(
                        prompt["input"],
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                },
            ],
            "stream": False,
            "keep_alive": -1,
            "format": ATTACK_SCHEMA,
            "options": options,
        }
        encoded = _canonical(payload).encode("utf-8")
        expected_hash = _sha256_bytes(encoded)
        if (
            attempt.get("request_payload_sha256") != expected_hash
            or attempt.get("request_payload_bytes") != len(encoded)
        ):
            raise ValueError(f"request payload mismatch for {attack_id}")
        request_hashes.add(expected_hash)
        request_bytes.append(len(encoded))

        runtime = attempt.get("runtime")
        if not isinstance(runtime, dict) or runtime.get("model") != args.model:
            raise ValueError(f"runtime model mismatch for {attack_id}")
        if runtime.get("done") is not True:
            raise ValueError(f"runtime did not report completion for {attack_id}")
        stop_reason = str(runtime.get("done_reason"))
        stop_reasons[stop_reason] += 1
        prompt_eval_counts.append(int(runtime["prompt_eval_count"]))
        eval_counts.append(int(runtime["eval_count"]))

    manifest = {
        "schema_version": "minmandate-stable-handle-gptoss-runtime-audit-v1",
        "run_id": args.run_id,
        "passed": True,
        "attacker": {
            "model": args.model,
            "digest": args.model_digest,
            **options,
            "role": "intent reconstruction only",
            "used_for_assembly": False,
        },
        "formal_attempt": {
            "prompt_count": len(prompt_rows),
            "prediction_count": len(prediction_rows),
            "attempt_count": len(attempt_rows),
            "failed_predictions": 0,
            "first_pass_schema_valid": first_pass_valid,
            "format_repairs": 0,
            "unique_attack_ids": len(expected_ids),
            "unique_request_payload_hashes": len(request_hashes),
            "request_payload_bytes": {
                "minimum": min(request_bytes),
                "maximum": max(request_bytes),
            },
            "prompt_eval_count": {
                "minimum": min(prompt_eval_counts),
                "maximum": max(prompt_eval_counts),
            },
            "eval_count": {
                "minimum": min(eval_counts),
                "maximum": max(eval_counts),
            },
            "stop_reasons": dict(sorted(stop_reasons.items())),
        },
        "prediction_sources": {
            str(path.resolve()): _sha256_file(path.resolve())
            for path in args.predictions
        },
        "attempt_sources": {
            str(path.resolve()): _sha256_file(path.resolve()) for path in args.attempts
        },
    }
    _write_json(output / "gptoss_runtime_audit.json", manifest)


def make_review(args: argparse.Namespace) -> None:
    output = args.output.resolve()
    prediction_rows: list[dict[str, Any]] = []
    for path in args.predictions:
        prediction_rows.extend(_read_jsonl(path.resolve()))
    predictions = {
        str(row["attack_id"]): str(row["prediction"]["reconstructed_intent"])
        for row in prediction_rows
        if row.get("status") == "valid_prediction"
    }
    private_rows = _read_jsonl(output / "private_score_map.jsonl")
    expected_ids = {str(row["attack_id"]) for row in private_rows}
    if set(predictions) != expected_ids:
        raise ValueError(
            f"prediction IDs differ from frozen prompts: "
            f"missing={sorted(expected_ids - set(predictions))}, "
            f"extra={sorted(set(predictions) - expected_ids)}"
        )

    review_rows: list[dict[str, Any]] = []
    private_review_map: list[dict[str, Any]] = []
    for private in private_rows:
        attack_id = str(private["attack_id"])
        review_id = "review_sh_" + hashlib.sha256(
            ("stable-handle-review-v1|" + attack_id).encode("utf-8")
        ).hexdigest()[:24]
        review_rows.append(
            {
                "original_user_intent": private["original_user_intent"],
                "reconstructed_intent": predictions[attack_id],
                "review_id": review_id,
                "semantic_equivalence_standard": SEMANTIC_EQUIVALENCE_STANDARD,
            }
        )
        private_review_map.append(
            {
                "attack_id": attack_id,
                "base_task_id": private["base_task_id"],
                "condition": "minmandate_stable_handle_joined",
                "review_id": review_id,
                "workflow_id": private["workflow_id"],
            }
        )

    # Sort by a review-only digest so the reviewer does not see source ordering.
    review_rows.sort(
        key=lambda row: hashlib.sha256(row["review_id"].encode("utf-8")).hexdigest()
    )
    private_review_map.sort(key=lambda row: row["review_id"])
    _write_jsonl(output / "blinded_intent_review_items.jsonl", review_rows)
    _write_jsonl(output / "private_intent_review_map.jsonl", private_review_map)

    with (output / "blinded_intent_review.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "review_id",
                "original_user_intent",
                "reconstructed_intent",
                "intent_semantically_equivalent",
                "notes",
                "semantic_equivalence_standard",
            ],
        )
        writer.writeheader()
        for row in review_rows:
            writer.writerow(
                {
                    **row,
                    "intent_semantically_equivalent": "",
                    "notes": "",
                }
            )

    _write_json(
        output / "review_manifest.json",
        {
            "schema_version": "minmandate-stable-handle-review-v1",
            "review_items": len(review_rows),
            "blinded_to_condition": True,
            "semantic_equivalence_standard": SEMANTIC_EQUIVALENCE_STANDARD,
            "prediction_sources": {
                str(path.resolve()): _sha256_file(path.resolve())
                for path in args.predictions
            },
            "blinded_items_sha256": _sha256_file(
                output / "blinded_intent_review_items.jsonl"
            ),
        },
    )


def score_review(args: argparse.Namespace) -> None:
    output = args.output.resolve()
    private_map = {
        str(row["review_id"]): row
        for row in _read_jsonl(output / "private_intent_review_map.jsonl")
    }
    with args.scores.resolve().open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if {str(row["review_id"]) for row in rows} != set(private_map):
        raise ValueError("review score IDs do not match the frozen review packet")

    scored: list[dict[str, Any]] = []
    for row in rows:
        raw = str(row["intent_semantically_equivalent"]).strip().lower()
        if raw not in {"true", "false"}:
            raise ValueError(
                f"review {row['review_id']} must be scored true or false, got {raw!r}"
            )
        scored.append(
            {
                "intent_semantically_equivalent": raw == "true",
                "notes": str(row.get("notes", "")),
                "review_id": str(row["review_id"]),
            }
        )
    scored.sort(key=lambda row: row["review_id"])
    _write_jsonl(output / "intent_reviewer_scores.jsonl", scored)
    successes = sum(bool(row["intent_semantically_equivalent"]) for row in scored)
    summary = {
        "schema_version": "minmandate-stable-handle-human-summary-v1",
        "condition": "minmandate_stable_handle_joined",
        "assembly_exact": 1.0,
        "human_semantic_recovery_count": successes,
        "workflow_count": len(scored),
        "human_semantic_recovery_rate": successes / len(scored),
        "human_semantic_recovery_percent": 100.0 * successes / len(scored),
        "review_scores_sha256": _sha256_file(
            output / "intent_reviewer_scores.jsonl"
        ),
    }
    _write_json(output / "human_summary.json", summary)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser(
        "build", help="build public stable-handle artifacts and frozen prompts"
    )
    build_parser.add_argument("--campaign", type=Path, required=True)
    build_parser.add_argument("--output", type=Path, required=True)
    build_parser.add_argument(
        "--run-id", default="minmandate-stable-handle-q32-real-wire-v1"
    )
    build_parser.add_argument(
        "--expected-workflows",
        type=int,
        default=96,
        help="number of tasks in the Q32 privacy cohort (paper default: 96)",
    )
    build_parser.set_defaults(func=build)

    validate_parser = subparsers.add_parser(
        "validate-private", help="open private truth after prompt freezing"
    )
    validate_parser.add_argument("--campaign", type=Path, required=True)
    validate_parser.add_argument("--output", type=Path, required=True)
    validate_parser.set_defaults(func=validate_private)

    audit_parser = subparsers.add_parser(
        "audit-runtime", help="verify frozen GPT-OSS request payloads and outputs"
    )
    audit_parser.add_argument("--output", type=Path, required=True)
    audit_parser.add_argument("--predictions", type=Path, nargs="+", required=True)
    audit_parser.add_argument("--attempts", type=Path, nargs="+", required=True)
    audit_parser.add_argument(
        "--run-id", default="minmandate-stable-handle-q32-real-wire-v1"
    )
    audit_parser.add_argument("--model", default="gpt-oss:120b")
    audit_parser.add_argument(
        "--model-digest",
        required=True,
        help="digest of the locally supplied model artifact",
    )
    audit_parser.add_argument("--temperature", type=float, default=0.0)
    audit_parser.add_argument("--top-p", type=float, default=1.0)
    audit_parser.add_argument("--seed", type=int, default=4411)
    audit_parser.add_argument("--num-ctx", type=int, default=32768)
    audit_parser.add_argument("--num-predict", type=int, default=1024)
    audit_parser.set_defaults(func=audit_runtime)

    review_parser = subparsers.add_parser(
        "make-review", help="create a blind human-review packet from predictions"
    )
    review_parser.add_argument("--output", type=Path, required=True)
    review_parser.add_argument("--predictions", type=Path, nargs="+", required=True)
    review_parser.set_defaults(func=make_review)

    score_parser = subparsers.add_parser(
        "score-review", help="score a completed blind-review CSV"
    )
    score_parser.add_argument("--output", type=Path, required=True)
    score_parser.add_argument("--scores", type=Path, required=True)
    score_parser.set_defaults(func=score_review)
    return parser


def main() -> None:
    args = _parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
