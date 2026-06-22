# SPDX-License-Identifier: MIT
"""Live secret validation against public APIs."""

import urllib.error
import urllib.request

SECRET_VALIDATORS: dict[str, tuple] = {
    "GitHub Token":        ("https://api.github.com/user", "GET", "token", 200, None),
    "GitHub Fine-grained": ("https://api.github.com/user", "GET", "Bearer", 200, None),
    "HuggingFace":         ("https://huggingface.co/api/whoami", "GET", "Bearer", 200, None),
    "npm token":           ("https://registry.npmjs.org/-/whoami", "GET", "Bearer", 200, None),
    "PyPI token":          ("https://pypi.org/pypi", "POST", None, None, "403_vs_401"),
}


def validate_secret(secret_type: str, value: str, timeout: int = 5) -> dict:
    """Call live APIs to verify whether a found secret is still active.

    Returns::

        {
            "valid": bool,
            "checked": bool,
            "details": str,
            "status_code": int | None,
        }

    ``checked=False`` indicates a network error, missing dependency, or
    no validator for this secret type.
    """
    result: dict = {"valid": False, "checked": False, "details": "", "status_code": None}

    validator = None
    for key, v in SECRET_VALIDATORS.items():
        if key.lower() in secret_type.lower():
            validator = v
            break
    if validator is None:
        result["details"] = "No validator available for this secret type"
        return result

    endpoint, method, auth_prefix, expected_status, predicate = validator
    headers = {"User-Agent": "omni-secret-scanner/9.0.0"}
    if auth_prefix:
        headers["Authorization"] = f"{auth_prefix} {value}"

    if predicate == "403_vs_401":
        try:
            req = urllib.request.Request(endpoint, method=method or "POST", headers=headers)
            resp = urllib.request.urlopen(req, timeout=timeout)
            result["status_code"] = resp.getcode()
            result["checked"] = True
            result["valid"] = False
            result["details"] = f"PyPI token granted access (status {resp.getcode()})"
        except urllib.error.HTTPError as e:
            result["status_code"] = e.code
            result["checked"] = True
            if e.code == 403:
                result["valid"] = True
                result["details"] = (
                    "PyPI token valid (received 403 Forbidden — token has account but no package perms)"
                )
            elif e.code == 401:
                result["valid"] = False
                result["details"] = "PyPI token invalid/expired (received 401 Unauthorized)"
            else:
                result["details"] = f"PyPI unexpected status {e.code}"
        except Exception as e:
            result["details"] = f"Network error: {str(e)[:120]}"
        return result

    try:
        req = urllib.request.Request(endpoint, method=method, headers=headers)
        resp = urllib.request.urlopen(req, timeout=timeout)
        result["status_code"] = resp.getcode()
        result["checked"] = True
        result["valid"] = resp.getcode() == expected_status
        result["details"] = f"API returned {resp.getcode()} (expected {expected_status})"
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["checked"] = True
        result["valid"] = False
        result["details"] = f"API returned {e.code} (expected {expected_status})"
    except Exception as e:
        result["details"] = f"Network error: {str(e)[:120]}"

    return result
