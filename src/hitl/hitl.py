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
                reason="\u0110i\u1ec3m tin c\u1eady kh\u00f4ng h\u1ee3p l\u1ec7 -- chuy\u1ec3n cho con ng\u01b0\u1eddi xem x\u00e9t",
                priority="high",
                requires_human=True,
            )

        if normalized_action in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=normalized_confidence,
                reason=f"H\u00e0nh \u0111\u1ed9ng r\u1ee7i ro cao: {normalized_action}",
                priority="high",
                requires_human=True,
            )

        if normalized_confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=normalized_confidence,
                reason="Ph\u1ea3n h\u1ed3i c\u00f3 \u0111\u1ed9 tin c\u1eady cao",
                priority="low",
                requires_human=False,
            )
        if normalized_confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=normalized_confidence,
                reason="Ph\u1ea3n h\u1ed3i c\u00f3 \u0111\u1ed9 tin c\u1eady trung b\u00ecnh c\u1ea7n ng\u01b0\u1eddi duy\u1ec7t x\u00e1c nh\u1eadn",
                priority="normal",
                requires_human=True,
            )
        return RoutingDecision(
            action="escalate",
            confidence=normalized_confidence,
            reason="Ph\u1ea3n h\u1ed3i c\u00f3 \u0111\u1ed9 tin c\u1eady th\u1ea5p -- chuy\u1ec3n c\u1ea5p x\u1eed l\u00fd",
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
        "name": "Phê duyệt chuyển tiền và người thụ hưởng",
        "trigger": "Mọi yêu cầu transfer_money, thêm người thụ hưởng mới hoặc thay đổi đáng kể số tiền/đích chuyển.",
        "hitl_model": "con người trong vòng lặp",
        "context_needed": "request_id, danh tính khách hàng đã xác thực, tài khoản nguồn/đích, lịch sử người thụ hưởng, số tiền/loại tiền, thay đổi giao dịch đề xuất, tín hiệu gian lận và kết quả chính sách egress.",
        "example": "Khách hàng đề nghị chuyển 50.000.000 VND đến người thụ hưởng vừa được thêm năm phút trước.",
        "proposed_action": "Chỉ thực hiện chuyển tiền sau khi reviewer phê duyệt và kiểm tra egress xác định lần cuối.",
        "approval_path": "Approve ghi reviewer_id và approval_id trước khi thực thi; reject không gửi giao dịch; timeout giữ và hết hạn yêu cầu, không tự thực thi.",
        "audit_fields": "request_id, thời điểm, user_id, intent, hành động/thay đổi đề xuất, tín hiệu rủi ro, reviewer_id, approval_id, quyết định, lý do và trạng thái timeout.",
        "audit_sink": "Bản ghi AuditLogPlugin theo request_id, xuất vào outputs/audit_log.json trong assignment suite.",
    },
    {
        "id": 2,
        "name": "Xác minh đóng tài khoản và thay đổi hồ sơ",
        "trigger": "close_account, change_password, update_personal_info hoặc thay đổi không thể đảo ngược về tài khoản/danh tính.",
        "hitl_model": "con người phân xử",
        "context_needed": "request_id, danh tính và phương thức xác thực, giá trị hiện tại/đề nghị, trạng thái tài khoản, sản phẩm liên kết, bằng chứng đồng ý và cảnh báo takeover gần đây.",
        "example": "Yêu cầu chat đóng tài khoản vẫn có khoản vay, đồng thời số điện thoại vừa thay đổi.",
        "proposed_action": "Chỉ áp dụng sau khi reviewer xác minh danh tính, đồng ý và điều kiện chính sách.",
        "approval_path": "Approve sau khi kiểm tra danh tính/chính sách; reject giữ nguyên trạng thái; timeout giữ yêu cầu và chuyển sang hỗ trợ bảo mật, không tự thực thi.",
        "audit_fields": "request_id, thời điểm, user_id, intent, giá trị hiện tại/đề nghị, bằng chứng đã xem, reviewer_id, quyết định, lý do, approval_id và kết quả timeout.",
        "audit_sink": "Bản ghi AuditLogPlugin theo request_id, xuất vào outputs/audit_log.json trong assignment suite.",
    },
    {
        "id": 3,
        "name": "Hỗ trợ có độ tin cậy thấp hoặc rủi ro gian lận",
        "trigger": "Độ tin cậy router dưới 0,70, chỉ thị khách hàng mâu thuẫn, sai lệch danh tính hoặc tín hiệu gian lận/bất thường có thể gây hại.",
        "hitl_model": "con người phân xử",
        "context_needed": "request_id, tin nhắn người dùng, phản hồi và độ tin cậy của model, provenance nguồn truy xuất, cảnh báo rủi ro tài khoản, chính sách liên quan và phản hồi dự kiến cho khách hàng.",
        "example": "Model chỉ 0,55 tự tin về yêu cầu gấp đổi người nhận sau một lần đăng nhập đáng ngờ.",
        "proposed_action": "Chỉ gửi phản hồi an toàn đã được reviewer duyệt hoặc chuyển hỗ trợ; không bao giờ tự thực hiện side effect.",
        "approval_path": "Approve chỉ gửi phản hồi/bước tiếp theo đã review; reject gửi thông báo chuyển cấp an toàn; timeout giữ action và mở case hỗ trợ/an ninh.",
        "audit_fields": "request_id, thời điểm, confidence, phiên bản model, provenance nguồn, phản hồi/hành động đề xuất, reviewer_id, quyết định, lý do, mã case escalation và trạng thái timeout.",
        "audit_sink": "Bản ghi AuditLogPlugin theo request_id, xuất vào outputs/audit_log.json trong assignment suite.",
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()


    test_cases = [
        ("Hỏi số dư", 0.95, "general"),
        ("Hỏi lãi suất", 0.82, "general"),
        ("Yêu cầu mơ hồ", 0.55, "general"),
        ("Chuyển 50.000 USD", 0.98, "transfer_money"),
        ("Đóng tài khoản", 0.91, "close_account"),
    ]

    print("Kiểm thử ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Kịch bản':<25} {'Tin cậy':<9} {'Loại hành động':<18} {'Quyết định':<15} {'Ưu tiên':<10} {'Cần người?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Có' if decision.requires_human else 'Không'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nCác điểm quyết định HITL:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Điểm quyết định #{point['id']}: {point['name']}")
        print(f"    Điều kiện: {point['trigger']}")
        print(f"    Mô hình:    {point['hitl_model']}")
        print(f"    Ngữ cảnh:  {point['context_needed']}")
        print(f"    Ví dụ:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
