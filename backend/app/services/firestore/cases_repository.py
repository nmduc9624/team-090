from typing import Any

from app.schemas.hunt_package import HuntPackage
from app.services.firestore.base import FirestoreRepository, utc_now_iso


class CasesRepository(FirestoreRepository):
    def create_or_update_case(
        self,
        package: HuntPackage,
        raw_report: dict[str, Any],
        user: Any | None = None,
    ) -> bool:
        case_id = package.package_id
        payload = {
            "case_id": case_id,
            "title": package.report_title,
            "severity": package.severity_hint,
            "confidence_score": package.confidence_score,
            "status": "open",
            "raw_report": raw_report,
            "owner_user_id": getattr(user, "uid", None),
            "created_by": getattr(user, "uid", None),
            "team_id": getattr(user, "team_id", ""),
            "created_at": utc_now_iso(),
            "updated_at": utc_now_iso(),
        }
        self.set_document(f"cases/{case_id}", payload)
        self.set_document(
            f"cases/{case_id}/hunt_packages/{package.package_id}",
            {
                **package.model_dump(mode="json"),
                "created_by": getattr(user, "uid", None),
                "created_at": utc_now_iso(),
            },
        )
        for action in package.priority_actions:
            self.set_document(
                f"cases/{case_id}/priority_actions/{action.action_id}",
                {
                    **action.model_dump(mode="json"),
                    "updated_at": utc_now_iso(),
                },
            )
        for step in package.investigation_flow:
            self.set_document(
                f"cases/{case_id}/steps/{step.step_id}",
                {
                    **step.model_dump(mode="json"),
                    "updated_at": utc_now_iso(),
                },
            )
        return True

    def update_case_status(self, case_id: str, status: str, user: Any | None = None) -> bool:
        return self.set_document(
            f"cases/{case_id}",
            {
                "status": status,
                "updated_at": utc_now_iso(),
                "updated_by": getattr(user, "uid", None),
            },
        )

    def update_priority_actions_confirmed(self, case_id: str, user: Any | None = None) -> bool:
        return self.set_document(
            f"cases/{case_id}",
            {
                "status": "in_progress",
                "priority_actions_confirmed": True,
                "priority_actions_confirmed_at": utc_now_iso(),
                "updated_at": utc_now_iso(),
                "updated_by": getattr(user, "uid", None),
            },
        )

    def mark_step_started(self, case_id: str, step: dict[str, Any], user: Any | None = None) -> bool:
        step_id = step.get("step_id") or step.get("title") or "unknown_step"
        self.set_document(
            f"cases/{case_id}/steps/{step_id}",
            {
                **step,
                "status": "started",
                "started_at": utc_now_iso(),
                "updated_at": utc_now_iso(),
                "updated_by": getattr(user, "uid", None),
            },
        )
        return self.set_document(
            f"cases/{case_id}",
            {
                "status": "in_progress",
                "active_step_id": step_id,
                "updated_at": utc_now_iso(),
                "updated_by": getattr(user, "uid", None),
            },
        )

    def list_user_cases(self, user_id: str, limit: int = 50) -> list[dict[str, Any]]:
        if not self.enabled:
            return []

        query = self.db.collection("cases").where("owner_user_id", "==", user_id).limit(limit)
        cases: list[dict[str, Any]] = []
        for doc in query.stream():
            data = doc.to_dict() or {}
            case_id = data.get("case_id") or doc.id
            unread_count = 0
            try:
                unread_count = sum(
                    1
                    for item in self.db.collection(f"users/{user_id}/notifications")
                    .where("case_id", "==", case_id)
                    .stream()
                    if not (item.to_dict() or {}).get("read")
                )
            except Exception:
                unread_count = 0
            cases.append({"case_id": case_id, "unread_notifications": unread_count, **data})
        cases.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
        return cases

    def get_user_case_detail(self, case_id: str, user_id: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None

        case_ref = self.db.document(f"cases/{case_id}")
        case_doc = case_ref.get()
        if not case_doc.exists:
            return None
        case_data = case_doc.to_dict() or {}
        if case_data.get("owner_user_id") != user_id and case_data.get("created_by") != user_id:
            return None

        def list_subcollection(name: str, limit: int = 100) -> list[dict[str, Any]]:
            items: list[dict[str, Any]] = []
            for doc in case_ref.collection(name).limit(limit).stream():
                items.append({"id": doc.id, **(doc.to_dict() or {})})
            return items

        hunt_packages = list_subcollection("hunt_packages", 5)
        audit_logs = sorted(list_subcollection("audit_logs"), key=lambda item: item.get("created_at", ""))
        warnings = sorted(list_subcollection("warnings"), key=lambda item: item.get("created_at", ""))
        help_requests = sorted(list_subcollection("help_requests"), key=lambda item: item.get("created_at", ""))
        notifications = sorted(list_subcollection("notifications"), key=lambda item: item.get("created_at", ""))
        steps = sorted(list_subcollection("steps"), key=lambda item: item.get("started_at", item.get("updated_at", "")))

        timeline = [
            *[
                {
                    "type": "audit",
                    "label": item.get("event", "audit event"),
                    "timestamp": item.get("created_at", ""),
                    "detail": item.get("target", ""),
                }
                for item in audit_logs
            ],
            *[
                {
                    "type": "warning",
                    "label": item.get("type", "warning"),
                    "timestamp": item.get("created_at", ""),
                    "detail": item.get("alert_title", ""),
                }
                for item in warnings
            ],
            *[
                {
                    "type": "help_request",
                    "label": "help requested",
                    "timestamp": item.get("created_at", ""),
                    "detail": item.get("question", ""),
                }
                for item in help_requests
            ],
            *[
                {
                    "type": "notification",
                    "label": "discord reply",
                    "timestamp": item.get("created_at", ""),
                    "detail": item.get("message", ""),
                }
                for item in notifications
            ],
        ]
        timeline.sort(key=lambda item: item.get("timestamp", ""))

        return {
            "case": {"case_id": case_id, **case_data},
            "hunt_package": hunt_packages[0] if hunt_packages else None,
            "steps": steps,
            "warnings": warnings,
            "help_requests": help_requests,
            "notifications": notifications,
            "timeline": timeline,
        }
