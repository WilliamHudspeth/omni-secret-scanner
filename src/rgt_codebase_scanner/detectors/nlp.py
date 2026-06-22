# SPDX-License-Identifier: MIT
"""NLP-based PII detection via spaCy / text-deidentification and Microsoft Presidio."""

import sys

SPACY_LANGUAGE_MODELS: dict[str, str] = {
    "en": "en_core_web_sm",
    "es": "es_core_news_sm",
    "fr": "fr_core_news_sm",
    "de": "de_core_news_sm",
    "pt": "pt_core_news_sm",
    "it": "it_core_news_sm",
    "nl": "nl_core_news_sm",
    "el": "el_core_news_sm",
    "ja": "ja_core_news_sm",
    "zh": "zh_core_web_sm",
    "ru": "ru_core_news_sm",
    "ko": "ko_core_news_sm",
    "xx": "xx_ent_wiki_sm",
}

PRESIDIO_LANGUAGE_MAP: dict[str, str] = {
    "en": "en",
    "es": "es",
    "fr": "fr",
    "de": "de",
    "pt": "pt",
    "it": "it",
    "nl": "nl",
    "ja": "ja",
    "zh": "zh",
    "ru": "ru",
    "ko": "ko",
    "ar": "ar",
}


def _normalize_language(lang: str) -> str:
    """Normalize a language input to a 2-letter ISO code, defaulting to ``en``."""
    if not lang:
        return "en"
    lang = lang.lower().strip()
    _map = {
        "english": "en",
        "spanish": "es",
        "español": "es",
        "french": "fr",
        "français": "fr",
        "german": "de",
        "deutsch": "de",
        "portuguese": "pt",
        "português": "pt",
        "italian": "it",
        "italiano": "it",
        "dutch": "nl",
        "nederlands": "nl",
        "japanese": "ja",
        "日本語": "ja",
        "chinese": "zh",
        "中文": "zh",
        "russian": "ru",
        "русский": "ru",
        "korean": "ko",
        "한국어": "ko",
        "arabic": "ar",
        "العربية": "ar",
        "greek": "el",
        "ελληνικά": "el",
    }
    if lang in _map:
        return _map[lang]
    if len(lang) == 2 and lang in SPACY_LANGUAGE_MODELS:
        return lang
    return "en"


def init_nlp_deidentifier(language: str = "en", quiet: bool = False):
    """Initialise the text-deidentification NLP pipeline.

    Returns a ``Deidentification`` instance, or ``None`` when the optional
    dependency is not installed.
    """
    try:
        from deidentification import Deidentification, DeidentificationConfig
    except ImportError:
        if not quiet:
            print(
                "Warning: 'text-deidentification' is not installed. "
                "NLP scanning will be skipped.\n"
                "Install with: pip install text-deidentification",
                file=sys.stderr,
            )
        return None

    lang_norm = _normalize_language(language)
    spacy_model = SPACY_LANGUAGE_MODELS.get(lang_norm, "en_core_web_sm")
    try:
        config = DeidentificationConfig(
            spacy_model=spacy_model, save_tokens=True, excluded_entities=set()
        )
        return Deidentification(config)
    except Exception as e:
        if not quiet:
            print(
                f"Warning: Error loading NLP model '{spacy_model}' "
                f"for language '{lang_norm}' ({e}). NLP scanning will be skipped.",
                file=sys.stderr,
            )
        return None


def init_presidio_analyzer(language: str = "en", quiet: bool = False):
    """Initialise the Microsoft Presidio NLP analyser.

    Returns an ``AnalyzerEngine`` instance, or ``None`` when the optional
    dependency is not installed.
    """
    try:
        from presidio_analyzer import AnalyzerEngine

        lang_norm = _normalize_language(language)
        presidio_lang = PRESIDIO_LANGUAGE_MAP.get(lang_norm, "en")
        analyzer = AnalyzerEngine()
        analyzer._omni_language = presidio_lang
        return analyzer
    except ImportError:
        if not quiet:
            print(
                "Warning: 'presidio-analyzer' is not installed. "
                "Presidio NLP scanning will be skipped.\n"
                "Install with: pip install presidio-analyzer",
                file=sys.stderr,
            )
        return None
