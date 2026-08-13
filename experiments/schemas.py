from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


EvidenceType = Literal[
    "measured_benchmark",
    "protocol_fixture",
    "measured_microbenchmark",
    "controlled_negative_test",
    "controlled_stress",
    "legacy_synthetic",
]


@dataclass(slots=True)
class EpisodeRecord:
    benchmark_name: str
    benchmark_version: str
    suite: str
    base_task_id: str
    episode_id: str
    condition: str
    condition_order: int
    model_id: str
    model_digest: str | None
    seed: int
    attack_mode: str
    defense_mode: str
    initial_state_hash: str
    final_state_hash: str
    task_success: bool
    evaluator_name: str
    evaluator_raw_output: dict[str, Any]
    number_of_llm_turns: int
    number_of_tool_calls: int
    number_of_paid_calls: int
    error_type: str | None
    error_message: str | None
    retry_count: int
    episode_start_wall_time: str
    episode_end_wall_time: str
    episode_duration_ms: float
    planner_ms: float
    tool_ms: float
    minmandate_ms: float
    other_orchestration_ms: float
    evidence_type: EvidenceType = "measured_benchmark"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ToolCallRecord:
    episode_id: str
    base_task_id: str
    suite: str
    call_id: str
    call_index: int
    tool_namespace: str
    tool_name: str
    canonical_tool_arguments: dict[str, Any]
    merchant_visible_descriptor: str
    service_class: str
    merchant_id: str
    paid: bool
    paid_mapping_rule: str
    tool_start_ns: int
    tool_end_ns: int
    tool_duration_ms: float
    result_hash: str
    result_size_bytes: int
    tool_success: bool
    middleware_variant: str
    middleware_accept: bool | None
    middleware_error: str | None
    middleware_latency_breakdown: dict[str, Any]
    price_quote_id: str | None = None
    quoted_price_nanos: int | None = None
    price_scenario: str | None = None
    tariff_config_sha256: str | None = None
    selected_slot_indices: list[int] = field(default_factory=list)
    selected_slot_denominations: list[int] = field(default_factory=list)
    selected_slot_capacity: int | None = None
    denomination_slack: int | None = None
    remaining_budget_after: int | None = None
    funding_coverage_remaining_after: int | None = None
    crypto_executed: bool = False
    crypto_scheme: str | None = None
    wire_schema_version: str | None = None
    view_count: int = 0
    issuer_hiding_crypto_executed: bool = False
    stable_issuer_handle_disclosed: bool = False
    evidence_type: EvidenceType = "measured_benchmark"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PaymentViewRecord:
    workflow_id: str
    base_task_id: str
    call_id: str
    call_index: int
    suite: str
    protocol: str
    protocol_version: str
    role: str
    coalition: str
    serialized_view: dict[str, Any]
    canonical_view_sha256: str
    wire_bytes: int
    schema_valid: bool
    schema_validation: str
    merchant_visible_descriptor: str
    service_class: str
    merchant_id: str
    quoted_price_nanos: int
    observed_at_ns: int
    trace_context_sha256: str
    evidence_type: EvidenceType
    validation_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


CompatibilityCondition = Literal["native", "policy_only", "full_minmandate"]


@dataclass(slots=True)
class MerchantCompatibilityRecord:
    schema_version: str
    track_id: str
    evidence_type: EvidenceType
    fixture_kind: str
    episode_id: str
    plan_episode_id: str
    episode_initial_state_hash: str
    call_id: str
    call_index: int
    condition_id: CompatibilityCondition
    condition: str
    merchant: str
    merchant_id: str
    tool: str
    service_class: str
    request_envelope: dict[str, Any]
    response_envelope: dict[str, Any]
    quote: dict[str, Any]
    credit_unit: str
    credit_before: int
    credit_delta: int
    credit_after: int
    budget_unit: str
    budget_before: int
    budget_after: int
    state_hash_before: str
    state_hash_after: str
    merchant_visible_descriptor: str
    descriptor_visibility: bool
    write_confirmation: str
    workspace_mutation_requested: bool
    workspace_mutated: bool
    accepted: bool
    denied: bool
    denial_reason: str | None
    policy_enforced: bool
    minmandate_adapter_used: bool
    protocol_metadata: dict[str, Any]
    live_proprietary_integration: bool
    formal_utility_denominator_inclusion: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
