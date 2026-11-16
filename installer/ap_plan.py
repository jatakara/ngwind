"""Fail-closed deterministic ERP AP deployment planning; no remote execution."""
import hashlib
import json

STEP_IDS = ("inventory", "backup", "redis", "dsm", "tomcat", "nginx", "health", "report")

def plan_ap(manifest, readiness=None, evidence=None, approval=None):
    if not isinstance(manifest, dict) or manifest.get("schema") != "omniesol-infra-readiness-v1":
        raise ValueError("Invalid inventory schema")
    deployment = manifest.get("deployment")
    if not isinstance(deployment, dict) or deployment.get("topology") not in ("erp_ap", "erp_ap_db", "erp_separated", "erp_uc"):
        raise ValueError("ERP AP topology required")
    servers = manifest.get("servers")
    if not isinstance(servers, list) or not any(isinstance(s, dict) and s.get("role") in ("ap", "ap_db") for s in servers):
        raise ValueError("AP role missing")
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    blockers = []
    if not isinstance(readiness, dict) or readiness.get("gate") != "GO":
        blockers.append("G1 readiness missing")
    if not isinstance(evidence, dict) or evidence.get("g2_status") != "VERIFIED":
        blockers.append("G2 independent live evidence missing")
    if not isinstance(approval, dict) or approval.get("g3_status") != "APPROVED":
        blockers.append("G3 authenticated approval missing")
    blockers.append("Execution engine and independent attestation not implemented")
    return {"schema": "omniesol-ap-plan-v1", "inventory_sha256": digest,
            "installation_gate": "HOLD", "execution_allowed": False,
            "mode": "OFFLINE_PLAN_ONLY", "blockers": blockers,
            "steps": [{"id": step, "depends_on": [] if i == 0 else [STEP_IDS[i-1]],
                       "state": "PENDING", "mode": "NOT_EXECUTABLE"}
                      for i, step in enumerate(STEP_IDS)]}
