"""Giao diện Streamlit tối giản cho VinBank Secure Demo."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import streamlit as st


REPO_ROOT = Path(__file__).resolve().parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

# Nạp provider trước khi import bất kỳ agent/guardrail nào. Output judge được
# khởi tạo ở import-time, nên thứ tự này bắt buộc để dùng NVIDIA NIM thay vì
# Google fallback.
from core.config import setup_api_key

setup_api_key()

from agents.agent import create_protected_agent
from assignment.pipeline import build_observability, build_production_plugins
from assignment.rate_limiter import RateLimitPlugin
from core.utils import chat_with_agent
from guardrails.input_guardrails import InputGuardrailPlugin, detect_injection, topic_filter
from guardrails.output_guardrails import OutputGuardrailPlugin, content_filter


st.set_page_config(page_title="VinBank Secure Demo", page_icon="🛡️", layout="centered")


def _find_plugin(plugins: list, plugin_type):
    return next(plugin for plugin in plugins if isinstance(plugin, plugin_type))


def initialise_chatbot() -> None:
    """Create one protected chatbot and audit stream per browser session."""
    if "chatbot" in st.session_state:
        return

    setup_api_key()
    plugins = build_production_plugins(max_requests=10, window_seconds=60)
    agent, runner = create_protected_agent(plugins)
    audit, monitor = build_observability()
    st.session_state.chatbot = {
        "agent": agent,
        "runner": runner,
        "audit": audit,
        "monitor": monitor,
        "rate_limiter": _find_plugin(plugins, RateLimitPlugin),
        "input_guard": _find_plugin(plugins, InputGuardrailPlugin),
        "output_guard": _find_plugin(plugins, OutputGuardrailPlugin),
        "adk_session_id": None,
    }
    st.session_state.messages = []


def layer_decision(bot: dict, before: tuple[int, int]) -> tuple[bool, str | None]:
    """Infer rate/output decisions; input is checked deterministically first."""
    before_rate, before_output = before
    if bot["rate_limiter"].blocked_count > before_rate:
        return True, "rate_limiter"
    if bot["output_guard"].blocked_count > before_output:
        return True, "llm_judge"
    return False, None


async def answer(message: str) -> tuple[str, bool, str | None, str]:
    """Execute the protected ADK agent and audit the complete interaction."""
    bot = st.session_state.chatbot
    audit = bot["audit"]
    monitor = bot["monitor"]
    request_id = audit.record_input(user_id="web_user", text=message)
    monitor.total_requests += 1
    # Pre-check xác định giúp input độc hại không chạm ADK/LLM, đồng thời cho
    # audit layer chính xác thay vì suy luận từ callback counter.
    if detect_injection(message):
        response = "Tôi không thể xử lý yêu cầu ghi đè hoặc tiết lộ hướng dẫn nội bộ. Tôi chỉ hỗ trợ nghiệp vụ VinBank."
        blocked, layer = True, "input_guardrail"
    elif topic_filter(message):
        response = "Tôi là trợ lý VinBank và chỉ hỗ trợ các câu hỏi liên quan đến ngân hàng."
        blocked, layer = True, "input_guardrail"
    else:
        before = (
            bot["rate_limiter"].blocked_count,
            bot["output_guard"].blocked_count,
        )
        try:
            response, session = await chat_with_agent(
                bot["agent"],
                bot["runner"],
                message,
                session_id=bot["adk_session_id"],
            )
            bot["adk_session_id"] = session.id
        except Exception:
            response = "Hệ thống tạm thời không thể xử lý yêu cầu. Vui lòng thử lại sau."
            blocked, layer = True, "system_error"
        else:
            blocked, layer = layer_decision(bot, before)

    # Defense in depth: never render unfiltered model text, even if a future
    # deployment accidentally changes an ADK callback.
    final_filter = content_filter(response)
    response = final_filter["redacted"]
    if not final_filter["safe"]:
        blocked = True
        layer = layer or "output_guardrail"

    if blocked:
        monitor.blocked_requests += 1
    if layer == "rate_limiter":
        monitor.rate_limit_hits += 1
    if layer == "llm_judge":
        monitor.judge_checks += 1
        monitor.judge_fails += 1

    audit.record_output(
        user_id="web_user",
        text=response,
        blocked=blocked,
        layer=layer,
        request_id=request_id,
    )
    monitor.check_metrics()
    return response, blocked, layer, request_id


def reset_conversation() -> None:
    """Reset the browser session without exposing API keys or audit contents."""
    st.session_state.pop("chatbot", None)
    st.session_state.pop("messages", None)


initialise_chatbot()
bot = st.session_state.chatbot

st.title("🛡️ VinBank Secure Demo")
st.caption("Chatbot minh hoạ lab: NVIDIA NIM + input/output guardrails + HITL/audit.")
st.warning("Bản demo học tập — không nhập dữ liệu cá nhân, số tài khoản hoặc thông tin xác thực thật.")

with st.sidebar:
    st.subheader("Trạng thái bảo vệ")
    st.metric("Rate limit", "10 yêu cầu / 60 giây")
    st.metric("Yêu cầu đã audit", bot["monitor"].total_requests)
    st.metric("Yêu cầu bị chặn", bot["monitor"].blocked_requests)
    if st.button("Bắt đầu hội thoại mới", use_container_width=True):
        reset_conversation()
        st.rerun()

for item in st.session_state.messages:
    with st.chat_message(item["role"]):
        st.write(item["content"])
        if item.get("layer"):
            st.caption(f"Lớp bảo vệ: {item['layer']} · Mã yêu cầu: {item['request_id']}")

prompt = st.chat_input("Ví dụ: Lãi suất tiết kiệm hiện tại là bao nhiêu?")
if prompt:
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.write(prompt)

    with st.chat_message("assistant"):
        with st.spinner("Đang kiểm tra guardrail và tạo phản hồi..."):
            response, blocked, layer, request_id = asyncio.run(answer(prompt))
        st.write(response)
        if blocked:
            st.caption(f"Yêu cầu được xử lý an toàn tại: {layer or 'lớp bảo vệ'}. Mã yêu cầu: {request_id}")
        else:
            st.caption(f"Mã yêu cầu: {request_id}")

    st.session_state.messages.append(
        {
            "role": "assistant",
            "content": response,
            "layer": layer if blocked else None,
            "request_id": request_id,
        }
    )