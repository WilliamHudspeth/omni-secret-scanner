# SPDX-License-Identifier: MIT
"""AI/LLM provider API key detection patterns (Wiz Research pattern set)."""

AI_PATTERNS: dict[str, str] = {
    "HuggingFace": r"hf_[A-Za-z0-9]{30,40}",
    "Groq": r"gsk_[A-Za-z0-9]{20,}",
    "Perplexity": r"pplx-[A-Za-z0-9]{20,}",
    "OpenAI": r"sk-(proj-)?[A-Za-z0-9]{20,}",
    "Anthropic": r"sk-ant-[A-Za-z0-9\-]{20,}",
    "WeightsAndBiases": r"(?i)wandb.*?[A-Za-z0-9]{40}",
    "AzureOpenAI": r"(?i)azure.*openai.*[A-Za-z0-9]{32}",
    "NVIDIA": r"nvapi-[A-Za-z0-9_\-]{20,}",
    "TogetherAI": r"[0-9a-f]{64}",
    "Cohere": r"(?i)cohere.*?[\'\"][A-Za-z0-9\-]{30,}[\'\"]",
    "Pinecone": r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    "Gemini": r"AIza[0-9A-Za-z\-_]{35}",
    "Moonshot": r"sk-[A-Za-z0-9]{20,}",
}
