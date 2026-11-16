import unittest
from installer.ap_plan import plan_ap

MANIFEST = {"schema": "omniesol-infra-readiness-v1",
            "deployment": {"topology": "erp_ap"},
            "servers": [{"role": "ap", "id": "ap1"}]}

class PlanTests(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(plan_ap(MANIFEST), plan_ap(MANIFEST))
        self.assertEqual(len(plan_ap(MANIFEST)["steps"]), 8)

    def test_forged_approval_does_not_enable_execution(self):
        result = plan_ap(MANIFEST, {"gate": "GO"}, {"g2_status": "VERIFIED"},
                         {"g3_status": "APPROVED"})
        self.assertFalse(result["execution_allowed"])
        self.assertEqual(result["installation_gate"], "HOLD")

    def test_invalid_manifest(self):
        with self.assertRaises(ValueError):
            plan_ap({"schema": "wrong"})
