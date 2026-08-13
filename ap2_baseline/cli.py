from __future__ import annotations

import argparse
import json
import time

from .audit import exact_join_metrics
from .domain import (
    AP2Profile,
    MerchantSpec,
    NeutralApproval,
    PaidToolCall,
    Quote,
    ToolAuthorization,
)
from .engine import AP2BaselineEngine


def smoke() -> int:
    merchant = MerchantSpec("web-service", "Web Service", "https://local.invalid")
    now = int(time.time())
    approval = NeutralApproval(
        task_id="smoke-task",
        currency="USD",
        total_budget_minor=1000,
        expires_at=now + 3600,
        tools=(
            ToolAuthorization(
                tool_id="web.search",
                title="Web search",
                service_class="web",
                merchant=merchant,
                max_calls=2,
                per_call_max_minor=500,
                allocated_budget_minor=1000,
            ),
        ),
    )
    engine = AP2BaselineEngine(approval, profile=AP2Profile.NATIVE)
    rows = []
    for i, amount in enumerate((300, 400), 1):
        call = PaidToolCall(
            workflow_id="wf-smoke",
            call_id=f"call-{i}",
            tool_id="web.search",
            title="Web search",
            service_class="web",
            arguments={"query": f"example {i}"},
            quote=Quote(amount, "USD", merchant, f"nonce-{i}"),
        )
        result = engine.execute(call)
        if not result.accepted:
            raise SystemExit(json.dumps(result.to_dict(False), indent=2))
        row = result.to_dict(include_tokens=False)
        row.update({"workflow_id": call.workflow_id, "call_id": call.call_id})
        rows.append(row)
    print(json.dumps({
        "calls": rows,
        "join": exact_join_metrics(rows, "checkout_root_jwt_sha256"),
    }, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["smoke"])
    args = parser.parse_args()
    if args.command == "smoke":
        return smoke()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
