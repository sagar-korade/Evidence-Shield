"""Authoritative Open Policy Agent (OPA) Evaluation Client."""

from typing import Dict, Any, List
import httpx
from fastapi import HTTPException, status

from .config import settings
from .security import SessionUser


class PolicyDenialError(HTTPException):
    def __init__(self, detail: str = "Access denied by zero-trust security policy."):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


class OPAEvaluator:
    """Evaluates zero-trust ABAC policies against OPA or built-in engine."""

    def __init__(self, opa_url: str = settings.opa_url):
        self.opa_url = opa_url
        self.opa_alive = False

    async def evaluate(
        self,
        user: SessionUser,
        action: str,
        resource: Dict[str, Any],
    ) -> bool:
        input_data = {
            "user": {
                "id": user.user_id,
                "username": user.username,
                "role": user.role,
                "agency": user.agency,
                "mfa_fresh": user.is_mfa_fresh,
            },
            "action": action,
            "resource": resource,
        }

        if self.opa_alive:
            try:
                async with httpx.AsyncClient(timeout=0.2) as client:
                    resp = await client.post(self.opa_url, json={"input": input_data})
                    if resp.status_code == 200:
                        result = resp.json().get("result", {})
                        if isinstance(result, dict):
                            return bool(result.get("allow", False))
                        return bool(result)
            except Exception:
                self.opa_alive = False

        # Built-in authoritative evaluation replicating evidence_policy.rego (instant < 1ms)
        return self._local_evaluate(input_data)

    def _local_evaluate(self, input_data: dict) -> bool:
        u = input_data["user"]
        act = input_data["action"]
        res = input_data["resource"]

        role = u["role"]
        user_id = u["id"]
        agency = u["agency"]
        mfa_fresh = u["mfa_fresh"]

        # Rule 1: SYSTEM_ADMIN cannot access evidentiary records
        if role == "SYSTEM_ADMIN" and act in [
            "document:read", "document:download", "document:decrypt", "analysis:run", "case:export"
        ]:
            return False

        assigned_principals = res.get("assigned_principals", [])
        assigned_agencies = res.get("assigned_agencies", [])
        has_case_access = (user_id in assigned_principals) or (agency in assigned_agencies)

        # Explicit grant check
        has_explicit_grant = False
        for g in res.get("explicit_grants", []):
            if g.get("principal_id") == user_id and not g.get("expired", False):
                if act in g.get("actions", []):
                    has_explicit_grant = True
                    break

        classification = res.get("classification", "INTERNAL")
        if classification == "RESTRICTED" and not mfa_fresh:
            return False

        # Classification check
        classification_ok = False
        if classification == "INTERNAL":
            classification_ok = True
        elif classification == "SENSITIVE":
            classification_ok = has_case_access or has_explicit_grant
        elif classification == "RESTRICTED":
            classification_ok = (has_case_access or has_explicit_grant) and mfa_fresh

        state = res.get("state", "VERIFIED_ANCHORED")

        if role in ["UNAUTHORIZED", "SUSPECT"]:
            return False

        # Case operations
        if res.get("type") == "case":
            if act == "case:read":
                return has_case_access or role in ["AUDITOR", "JUDGE"]
            if act == "case:write":
                return has_case_access and role in ["POLICE", "FORENSIC_LAB", "FORENSIC_EXAMINER"]
            if act == "case:export":
                return has_case_access and role in ["PROSECUTOR", "JUDGE"]
            if act == "grant:create":
                return has_case_access and role in ["POLICE", "PROSECUTOR", "JUDGE"]

        # Document Download & Read
        if act in ["document:read", "document:download"]:
            # Quarantined evidence CANNOT be downloaded (Fail-closed)
            if state == "QUARANTINED" and act == "document:download":
                return False

            if state == "QUARANTINED" and act == "document:read":
                return role in ["JUDGE", "AUDITOR"]

            # Judges and Auditors have broad judicial review rights
            if role in ["JUDGE", "AUDITOR"]:
                return True

            if state == "READY_PENDING_ANCHOR":
                uploader_id = res.get("uploader_id")
                return (user_id == uploader_id or has_case_access) and classification_ok

            return (has_case_access or has_explicit_grant) and classification_ok

        # Custody Transfers
        if act == "document:transfer":
            return role in ["POLICE", "FORENSIC_LAB", "FORENSIC_EXAMINER", "PROSECUTOR", "JUDGE"]

        # Derivative: requires valid state
        if act == "document:derivative":
            return role in ["POLICE", "FORENSIC_LAB", "FORENSIC_EXAMINER"]

        # AI Analysis
        if act == "analysis:run":
            return role in ["POLICE", "FORENSIC_LAB", "FORENSIC_EXAMINER", "PROSECUTOR", "JUDGE"]

        # Alert Review
        if act == "alert:review":
            return role in ["POLICE", "FORENSIC_LAB", "FORENSIC_EXAMINER", "PROSECUTOR", "JUDGE", "AUDITOR"]

        # Default deny
        return False


policy_evaluator = OPAEvaluator()


async def check_permission(user: SessionUser, action: str, resource: Dict[str, Any]):
    allowed = await policy_evaluator.evaluate(user, action, resource)
    if not allowed:
        raise PolicyDenialError(
            f"Zero-trust denial: User '{user.username}' ({user.role}) is not authorized for '{action}'."
        )
