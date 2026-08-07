"""
Lab 11 — Part 4: Human-in-the-Loop Design
  TODO 11: Confidence Router
  TODO 12: Design 3 HITL decision points
"""
from dataclasses import dataclass
import math


# ============================================================
# TODO 11: Implement ConfidenceRouter
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        # TODO 11: Implement routing logic
        #
        # 1. Check if action_type is in HIGH_RISK_ACTIONS
        #    -> If yes: always escalate (action="escalate", priority="high",
        #       requires_human=True, reason="High-risk action: {action_type}")
        #
        # 2. Check confidence thresholds:
        #    - confidence >= 0.9:
        #      action="auto_send", priority="low",
        #      requires_human=False, reason="High confidence"
        #
        #    - 0.7 <= confidence < 0.9:
        #      action="queue_review", priority="normal",
        #      requires_human=True, reason="Medium confidence — needs review"
        #
        #    - confidence < 0.7:
        #      action="escalate", priority="high",
        #      requires_human=True, reason="Low confidence — escalating"

        try:
            normalized_confidence = float(confidence)
        except (TypeError, ValueError):
            normalized_confidence = float("nan")

        # Invalid confidence must fail closed instead of being treated as a
        # high-confidence answer. Normalize the action name to avoid a casing
        # variation bypassing the high-risk policy.
        normalized_action = str(action_type).strip().casefold()
        if (
            not math.isfinite(normalized_confidence)
            or not 0.0 <= normalized_confidence <= 1.0
        ):
            return RoutingDecision(
                action="escalate",
                confidence=normalized_confidence,
                reason="Invalid confidence score -- escalating for human review",
                priority="high",
                requires_human=True,
            )

        if normalized_action in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=normalized_confidence,
                reason=f"High-risk action: {normalized_action}",
                priority="high",
                requires_human=True,
            )

        if normalized_confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=normalized_confidence,
                reason="High confidence response",
                priority="low",
                requires_human=False,
            )
        if normalized_confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=normalized_confidence,
                reason="Medium confidence response needs reviewer confirmation",
                priority="normal",
                requires_human=True,
            )
        return RoutingDecision(
            action="escalate",
            confidence=normalized_confidence,
            reason="Low confidence response -- escalating",
            priority="high",
            requires_human=True,
        )


# ============================================================
# TODO 12: Design 3 HITL decision points + a review lifecycle
#
# For each decision point, define:
# - trigger: What condition activates this HITL check?
# - hitl_model: Which model? (human-in-the-loop, human-on-the-loop,
#   human-as-tiebreaker)
# - context_needed: What info does the human reviewer need?
# - example: A concrete scenario
# - approval_path: What approve/reject/timeout decision is recorded?
# - audit_fields: Which correlation ID, intent and proposed action/diff are logged?
#
# Think about real banking scenarios where human judgment is critical.
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "Transfer and beneficiary approval",
        "trigger": "Any transfer_money request, a new beneficiary, or a material change to transfer amount or destination.",
        "hitl_model": "human-in-the-loop",
        "context_needed": "request_id, authenticated customer identity, source and destination accounts, beneficiary history, amount/currency, proposed transfer diff, fraud signals, and egress-policy result.",
        "example": "Customer proposes a 50,000,000 VND transfer to a beneficiary added five minutes ago.",
        "proposed_action": "Execute the transfer only after reviewer approval and a final deterministic egress-policy check.",
        "approval_path": "Approve records reviewer ID and approval ID before execution; reject sends no transfer; timeout holds the request and expires it without execution.",
        "audit_fields": "request_id, timestamp, user_id, intent, proposed action and diff, risk signals, reviewer_id, approval_id, decision, rationale, and timeout status.",
        "audit_sink": "AuditLogPlugin record for request_id, exported to outputs/audit_log.json during the assignment suite.",
    },
    {
        "id": 2,
        "name": "Account closure and profile-change verification",
        "trigger": "close_account, change_password, update_personal_info, or another irreversible account or identity change.",
        "hitl_model": "human-as-tiebreaker",
        "context_needed": "request_id, verified identity and authentication method, current versus requested profile values, account status, linked products, consent evidence, and recent account-takeover alerts.",
        "example": "A chat request asks to close an account that still has a loan repayment and a newly changed phone number.",
        "proposed_action": "Apply the requested closure or profile change only after the reviewer verifies identity, consent, and policy eligibility.",
        "approval_path": "Approve only after identity and policy checks; reject preserves the current account state; timeout holds the request and routes it to secure support, never auto-executing it.",
        "audit_fields": "request_id, timestamp, user_id, intent, current and proposed values, evidence reviewed, reviewer_id, decision, rationale, approval_id, and timeout outcome.",
        "audit_sink": "AuditLogPlugin record for request_id, exported to outputs/audit_log.json during the assignment suite.",
    },
    {
        "id": 3,
        "name": "Low-confidence or fraud-sensitive assistance",
        "trigger": "Router confidence below 0.70, conflicting customer instructions, identity mismatch, or fraud/anomaly signal on a request that could mislead the customer.",
        "hitl_model": "human-as-tiebreaker",
        "context_needed": "request_id, user message, model response and confidence, retrieved-source provenance, account-risk alerts, relevant policy, and the proposed customer-facing reply.",
        "example": "The model is 0.55 confident about an urgent request to change a transfer recipient after a suspicious login.",
        "proposed_action": "Send only a reviewer-approved safe reply or escalate to support; never perform the requested side effect automatically.",
        "approval_path": "Approve sends only the reviewed reply or next step; reject sends a safe escalation message; timeout keeps the action on hold and opens a support/security case.",
        "audit_fields": "request_id, timestamp, confidence, model version, source provenance, proposed reply/action, reviewer_id, decision, rationale, escalation case ID, and timeout status.",
        "audit_sink": "AuditLogPlugin record for request_id, exported to outputs/audit_log.json during the assignment suite.",
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
