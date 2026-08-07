"""Model-provider factory used by every live ADK agent in this lab."""
import os

from google.adk.models.lite_llm import LiteLlm


def get_model():
    """Return the configured ADK model without exposing credentials in code."""
    provider = os.environ.get("LLM_PROVIDER", "google").strip().lower()
    if provider == "nvidia_nim":
        return LiteLlm(
            model=os.environ["NVIDIA_NIM_MODEL"],
            api_key=os.environ["NVIDIA_NIM_API_KEY"],
            api_base=os.environ["NVIDIA_NIM_API_BASE"],
            drop_params=True,
        )
    if provider in {"google", "gemini"}:
        return "gemini-3.1-flash-lite"
    raise RuntimeError(f"LLM_PROVIDER kh\u00f4ng \u0111\u01b0\u1ee3c h\u1ed7 tr\u1ee3: {provider}")
