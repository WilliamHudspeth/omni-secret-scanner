# SPDX-License-Identifier: MIT
"""PII (Personally Identifiable Information) regex pattern library."""

# Numeric constants that look like PII but are common code values
# (iteration counts, timeouts in seconds, port numbers, threshold values)
PII_IGNORE_VALUES: set[str] = {
    "10000", "15000", "20000", "30000", "50000",
    "32768", "65535", "65536",
    "86400",  # seconds in a day
    "99999",
}

CUSTOM_PII_PATTERNS: dict[str, str] = {
    "Email Address": r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    "Phone Number (US)": r"\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}",
    "SSN (US)": r"(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}",
    "Street Address (simple)": (
        r"\d{1,5}\s[A-Za-z0-9\s]+"
        r"(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct)\b"
    ),
    "Zip Code (US)": r"\b\d{5}(-\d{4})?\b",
    "Credit Card": (
        r"\b(?:4[0-9]{3}(?:[-\s]?[0-9]{4}){3}"
        r"|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)"
        r"[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}"
        r"|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}"
        r"|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b"
    ),
    "IBAN": r"\b[A-Z]{2}\d{2}(?:[-\s]?[A-Z0-9]){12,30}\b",
}
