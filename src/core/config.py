"""
Lab 11 — Configuration & API Key Setup
"""
import os
from pathlib import Path

from dotenv import load_dotenv


def setup_api_key():
    """Load the configured model provider credentials from the repo .env file."""
    repo_env = Path(__file__).resolve().parents[2] / ".env"
    load_dotenv(repo_env, override=False)
    provider = os.environ.get("LLM_PROVIDER", "google").strip().lower()

    if provider == "nvidia_nim":
        required = (
            "NVIDIA_NIM_API_KEY",
            "NVIDIA_NIM_API_BASE",
            "NVIDIA_NIM_MODEL",
        )
        missing = [name for name in required if not os.environ.get(name, "").strip()]
        if missing:
            raise RuntimeError(
                "\u0110\u00e3 ch\u1ecdn NVIDIA NIM nh\u01b0ng thi\u1ebfu bi\u1ebfn: " + ", ".join(missing)
            )
        print("\u0110\u00e3 n\u1ea1p c\u1ea5u h\u00ecnh API NVIDIA NIM.")
        return

    if provider in {"google", "gemini"}:
        if "GOOGLE_API_KEY" not in os.environ:
            os.environ["GOOGLE_API_KEY"] = input("Nh\u1eadp Google API Key: ")
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
        print("\u0110\u00e3 n\u1ea1p c\u1ea5u h\u00ecnh API Google Gemini.")
        return

    raise RuntimeError(
        "LLM_PROVIDER kh\u00f4ng \u0111\u01b0\u1ee3c h\u1ed7 tr\u1ee3. H\u00e3y d\u00f9ng 'nvidia_nim', 'google' ho\u1eb7c 'gemini'."
    )


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "chuyen khoan", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
