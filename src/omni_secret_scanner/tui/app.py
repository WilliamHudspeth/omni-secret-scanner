# SPDX-License-Identifier: MIT
"""Interactive terminal user interface — arrow-key navigated menus."""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Low-level terminal helpers
# ---------------------------------------------------------------------------


def get_key() -> str:
    """Read a single keypress and return a normalised name."""
    if sys.platform == "win32":
        import msvcrt

        try:
            ch = msvcrt.getch()
        except KeyboardInterrupt:
            return "ctrl-c"
        if ch in (b"\x00", b"\xe0"):
            try:
                ch2 = msvcrt.getch()
            except KeyboardInterrupt:
                return "ctrl-c"
            if ch2 == b"H":
                return "up"
            if ch2 == b"P":
                return "down"
            if ch2 == b"K":
                return "left"
            if ch2 == b"M":
                return "right"
        if ch == b"\r":
            return "enter"
        if ch == b"\x1b":
            return "escape"
        if ch == b"\x03":
            return "ctrl-c"
        try:
            return ch.decode("utf-8").lower()
        except Exception:
            return ""
    else:
        import select
        import termios
        import tty

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                r, _, _ = select.select([sys.stdin], [], [], 0.05)
                if r:
                    ch2 = sys.stdin.read(2)
                    if ch2 == "[A":
                        return "up"
                    if ch2 == "[B":
                        return "down"
                    if ch2 == "[D":
                        return "left"
                    if ch2 == "[C":
                        return "right"
                return "escape"
            if ch in ("\n", "\r"):
                return "enter"
            if ch == "\x03":
                return "ctrl-c"
            return ch.lower()
        except KeyboardInterrupt:
            return "ctrl-c"
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


# ---------------------------------------------------------------------------
# Menu rendering
# ---------------------------------------------------------------------------


def menu_picker(title: str, options: list[str], selected_idx: int) -> None:
    clear_screen()
    print("\033[1;36m============================================================\033[0m")
    print(f"\033[1;36m  {title}\033[0m")
    print("\033[1;36m============================================================\033[0m")
    print("Use UP/DOWN arrow keys to navigate, ENTER to select, ESC/Q to exit.\n")
    for idx, opt in enumerate(options):
        if idx == selected_idx:
            print(f" \033[1;32m--> [ {opt} ]\033[0m")
        else:
            print(f"     [ {opt} ]")
    print()


# ---------------------------------------------------------------------------
# Findings viewer
# ---------------------------------------------------------------------------


def view_findings_menu(
    findings: list[dict],
    state: dict,
    snippet_content: str | None = None,
) -> None:
    from ..reporters.base import injection_risk_score  # noqa: F401 (unused here)
    from ..utils.git import get_context_snippet
    from ..utils.redaction import redact_match

    if not findings:
        clear_screen()
        print("\033[1;32mNo findings found! Code is clean.\033[0m")
        print("\nPress any key to return to Main Menu...")
        get_key()
        return

    history_secrets_count = sum(1 for f in findings if f["category"] == "History Secret")
    tree_secrets_count = sum(1 for f in findings if f["category"] == "Tree Secret")
    pii_count = sum(
        1 for f in findings if f["category"] in ("History PII", "NLP PII", "PS Crosscheck")
    )
    entropy_count = sum(1 for f in findings if f["category"] == "History Entropy")
    semgrep_count = sum(1 for f in findings if f["category"] == "Semgrep SAST")

    score = (
        100
        - (history_secrets_count + tree_secrets_count) * 40
        - pii_count * 20
        - entropy_count * 10
        - semgrep_count * 10
    )
    score = max(0, min(100, score))

    if score < 50:
        risk_label, risk_color = "RED (High Risk - Do Not Share)", "\033[1;31m"
    elif score < 90:
        risk_label, risk_color = "YELLOW (Medium Risk - Inspect Before Sharing)", "\033[1;33m"
    else:
        risk_label, risk_color = "GREEN (Safe to Share)", "\033[1;32m"

    selected = 0
    scroll_offset = 0
    page_size = 8

    while True:
        clear_screen()
        print("\033[1;36m============================================================\033[0m")
        print("\033[1;36m  SCAN RESULTS EXPLORER\033[0m")
        print("\033[1;36m============================================================\033[0m")
        print(f"Safety Score: {risk_color}{score}/100 - {risk_label}\033[0m")
        print(
            f"Detections: Secrets={history_secrets_count + tree_secrets_count} "
            f"PII={pii_count} High-Entropy={entropy_count} Semgrep={semgrep_count}\n"
        )
        print(
            "Use UP/DOWN arrow keys to navigate, R to generate filter-repo scrub commands, ESC/Q to return.\n"
        )

        if selected < scroll_offset:
            scroll_offset = selected
        elif selected >= scroll_offset + page_size:
            scroll_offset = selected - page_size + 1

        for i in range(scroll_offset, min(len(findings), scroll_offset + page_size)):
            f = findings[i]
            prefix = "--> " if i == selected else "    "
            mask_val = redact_match(f["match"]) if state["mask"] else f["match"]
            display_line = (
                f"{prefix}[{f['category']}: {f['type']}] {f['file']}:{f['line']} -> {mask_val}"
            )
            if i == selected:
                print(f"\033[1;32m{display_line}\033[0m")
            else:
                print(display_line)

        if len(findings) > page_size:
            print(
                f"\n   [ Showing {scroll_offset + 1}-{min(len(findings), scroll_offset + page_size)} of {len(findings)} findings ]"
            )

        print("\033[1;36m------------------------------------------------------------\033[0m")
        print("\033[1mDETAILED FINDING VIEW\033[0m")
        print("\033[1;36m------------------------------------------------------------\033[0m")

        sel_f = findings[selected]
        m_val = redact_match(sel_f["match"]) if state["mask"] else sel_f["match"]
        print(f"Category: {sel_f['category']}")
        print(f"Type:     {sel_f['type']}")
        print(f"File/Ref: {sel_f['file']} (Line: {sel_f['line']})")
        print(f"Match:    {m_val}")
        if "entropy" in sel_f:
            print(f"Entropy:  {sel_f['entropy']}")

        if state["context_lines"] > 0 and sel_f["line"] != "?":
            context = get_context_snippet(
                sel_f["file"], sel_f["line"], state["context_lines"], content=snippet_content
            )
            if context:
                if state["mask"]:
                    context = context.replace(sel_f["match"], redact_match(sel_f["match"]))
                print("\nContext:")
                print(context)

        print("\nLLM Remediation Prompt Snippet:")
        print(
            f"- {sel_f['type']} in {sel_f['file']}:{sel_f['line']} -> {redact_match(sel_f['match'])}"
        )

        key = get_key()
        if key == "up":
            selected = (selected - 1) % len(findings)
        elif key == "down":
            selected = (selected + 1) % len(findings)
        elif key == "r":
            _generate_filter_repo_interactive(findings)
        elif key in ("escape", "q"):
            break


def _generate_filter_repo_interactive(findings: list[dict]) -> None:
    clear_screen()
    print("\033[1;36m============================================================\033[0m")
    print("\033[1;36m  GENERATING SCRUB REMEDIATION COMMAND...\033[0m")
    print("\033[1;36m============================================================\033[0m")

    unique_secrets = {f["match"].strip() for f in findings if f["match"].strip()}
    if unique_secrets:
        with open("replacements.txt", "w", encoding="utf-8") as fout:
            for sec in sorted(unique_secrets):
                fout.write(f"{sec}==>[REDACTED]\n")
        print(f"Generated replacements.txt with {len(unique_secrets)} unique secrets.")

        gitignore_path = Path(".gitignore")
        if gitignore_path.exists():
            try:
                lines = gitignore_path.read_text(encoding="utf-8").splitlines()
                already_there = any("replacements.txt" in line for line in lines)
            except Exception:
                already_there = False
        else:
            already_there = False

        if not already_there:
            try:
                with open(gitignore_path, "a", encoding="utf-8") as fg:
                    fg.write("\n# Omni-Secret-Scanner filter-repo replacements\nreplacements.txt\n")
                print("Added replacements.txt to .gitignore")
            except Exception:
                pass

        print("\nTo scrub these secrets from your repository history, run:")
        print("  \033[1;32mgit filter-repo --replace-text replacements.txt --force\033[0m")
    else:
        print("No credentials or PII were found to redact.")

    print("\nPress any key to return to results...")
    get_key()


# ---------------------------------------------------------------------------
# Settings menu
# ---------------------------------------------------------------------------


def configure_settings_menu(state: dict) -> None:
    selected = 0
    while True:
        options = [
            f"Toggle Masking: [{'ENABLED' if state['mask'] else 'DISABLED'}]",
            f"Entropy Threshold: [{state['entropy_threshold']}]",
            f"Context Lines: [{state['context_lines']}]",
            f"Sensitive Words: [{','.join(state['sensitive_words']) if state['sensitive_words'] else '(none)'}]",
            f"Enable NLP (spaCy): [{'ENABLED' if state['nlp_pii'] else 'DISABLED'}]",
            f"Enable PowerShell Crosscheck: [{'ENABLED' if state['ps_crosscheck'] else 'DISABLED'}]",
            f"Extract Code Blocks: [{'ENABLED' if state['extract_code_blocks'] else 'DISABLED'}]",
            f"Enable Reflog Scan: [{'ENABLED' if state['reflog'] else 'DISABLED'}]",
            f"Since Limit: [{state['since'] if state['since'] else '(all)'}]",
            f"Scan Submodules: [{'ENABLED' if state.get('submodules', False) else 'DISABLED'}]",
            f"Enable Presidio NLP: [{'ENABLED' if state.get('presidio', False) else 'DISABLED'}]",
            f"Enable Semgrep SAST: [{'ENABLED' if state.get('semgrep', False) else 'DISABLED'}]",
            "Go Back to Main Menu",
        ]
        menu_picker("SETTINGS CONFIGURATION", options, selected)
        key = get_key()
        if key == "up":
            selected = (selected - 1) % len(options)
        elif key == "down":
            selected = (selected + 1) % len(options)
        elif key == "escape":
            break
        elif key == "enter":
            _handle_settings_selection(selected, state)
            if selected == len(options) - 1:
                break


def _handle_settings_selection(selected: int, state: dict) -> None:
    if selected == 0:
        state["mask"] = not state["mask"]
    elif selected == 1:
        clear_screen()
        val = input(
            f"Enter new Entropy Threshold (current: {state['entropy_threshold']}): "
        ).strip()
        try:
            state["entropy_threshold"] = float(val)
        except ValueError:
            pass
    elif selected == 2:
        clear_screen()
        val = input(f"Enter new Context Lines (current: {state['context_lines']}): ").strip()
        try:
            state["context_lines"] = int(val)
        except ValueError:
            pass
    elif selected == 3:
        clear_screen()
        current = ",".join(state["sensitive_words"])
        val = input(f"Enter Sensitive Words (comma-separated, current: {current}): ").strip()
        state["sensitive_words"] = [w.strip() for w in val.split(",") if w.strip()]
    elif selected == 4:
        state["nlp_pii"] = not state["nlp_pii"]
    elif selected == 5:
        state["ps_crosscheck"] = not state["ps_crosscheck"]
    elif selected == 6:
        state["extract_code_blocks"] = not state["extract_code_blocks"]
    elif selected == 7:
        state["reflog"] = not state["reflog"]
    elif selected == 8:
        clear_screen()
        current = state["since"] or "(all)"
        val = input(
            f"Enter new Since Limit (e.g. HEAD~3, 2026-06-01, empty for all; current: {current}): "
        ).strip()
        state["since"] = val if val else None
    elif selected == 9:
        state["submodules"] = not state.get("submodules", False)
    elif selected == 10:
        state["presidio"] = not state.get("presidio", False)
    elif selected == 11:
        state["semgrep"] = not state.get("semgrep", False)


# ---------------------------------------------------------------------------
# Scan actions
# ---------------------------------------------------------------------------


def run_tui_repo_scan(state: dict) -> None:
    from ..detectors import (
        init_nlp_deidentifier,
        init_presidio_analyzer,
        run_ps_crosscheck,
        run_semgrep_scan,
        scan_current_tree,
        scan_history,
        scan_reflog,
    )
    from ..reporters.base import flatten_findings, injection_risk_score
    from ..utils.git import load_secretsignore

    clear_screen()
    print("\033[1;36m============================================================\033[0m")
    print("\033[1;36m  RUNNING REPOSITORY SCAN...\033[0m")
    print("\033[1;36m============================================================\033[0m")
    print("This may take a few moments depending on repository size.\n")

    ignore_files, ignore_tokens = load_secretsignore(state["repo_dir"])

    exclude_patterns = [
        "*.lock",
        "*.svg",
        "*.png",
        "*.jpg",
        "*.jpeg",
        "*.gif",
        "*.ico",
        "*.woff*",
        "*.ttf",
        "*.eot",
        "*.min.js",
        "*.min.css",
        "package-lock.json",
        "*.sum",
        ".gitignore",
        ".gitattributes",
        ".git/",
        "node_modules/",
        "vendor/",
        "dist/",
        "build/",
        "__pycache__/",
        "*.pyc",
    ]
    exclude_patterns.extend(ignore_files)

    nlp_deidentifier = None
    if state["nlp_pii"]:
        print("Initializing NLP Engine...")
        nlp_deidentifier = init_nlp_deidentifier(quiet=True)

    presidio_analyzer = None
    if state.get("presidio", False):
        print("Initializing Presidio NLP Engine...")
        presidio_analyzer = init_presidio_analyzer(quiet=True)

    ps_findings: list[dict] = []
    if state["ps_crosscheck"]:
        print("Running PowerShell Crosscheck...")
        ps_findings = run_ps_crosscheck(state["repo_dir"], quiet=True, ignore_tokens=ignore_tokens)

    print("Scanning Git history...")
    history_findings = scan_history(
        exclude_patterns,
        all_branches=False,
        quiet=True,
        entropy_threshold=state["entropy_threshold"],
        ignore_tokens=ignore_tokens,
        sensitive_words=state["sensitive_words"],
        since=state["since"],
        scan_submodules=state.get("submodules", False),
    )

    if state["reflog"]:
        print("Scanning Git reflog history...")
        reflog_findings = scan_reflog(
            exclude_patterns,
            quiet=True,
            entropy_threshold=state["entropy_threshold"],
            ignore_tokens=ignore_tokens,
            sensitive_words=state["sensitive_words"],
        )
        history_findings["secrets"].extend(reflog_findings["secrets"])
        history_findings["pii"].extend(reflog_findings["pii"])
        history_findings["entropy"].extend(reflog_findings["entropy"])
        history_findings["injections"].extend(reflog_findings.get("injections", []))

    print("Scanning current files...")
    tree_findings = scan_current_tree(
        state["repo_dir"],
        exclude_patterns,
        nlp_deidentifier,
        quiet=True,
        ignore_tokens=ignore_tokens,
        sensitive_words=state["sensitive_words"],
        extract_code_blocks=state["extract_code_blocks"],
        scan_submodules=state.get("submodules", False),
        presidio_analyzer=presidio_analyzer,
    )

    semgrep_findings: list[dict] = []
    if state.get("semgrep", False):
        print("Running Semgrep AST Static Analysis...")
        semgrep_findings = run_semgrep_scan(state["repo_dir"], quiet=True)

    injection_findings = history_findings.get("injections", []) + tree_findings.get(
        "injections", []
    )
    inj_risk = injection_risk_score(injection_findings)

    print("Compiling findings...")
    findings = flatten_findings(
        history_findings, tree_findings, ps_findings, semgrep_findings=semgrep_findings
    )

    # Persist report for later loading
    try:
        score = 100
        score -= (len(history_findings["secrets"]) + len(tree_findings["current_secrets"])) * 40
        score -= (
            len(history_findings["pii"]) + len(tree_findings["nlp_pii"]) + len(ps_findings)
        ) * 20
        score -= len(history_findings["entropy"]) * 10
        score -= len(semgrep_findings) * 10
        score = max(0, min(100, score))

        report = {
            "scan_time": datetime.now().isoformat(),
            "summary": {
                "total_issues": len(findings),
                "has_secrets": bool(
                    history_findings["secrets"] or tree_findings["current_secrets"]
                ),
                "has_pii": bool(history_findings["pii"] or tree_findings["nlp_pii"] or ps_findings),
                "safety_score": score,
                "injection_risk": inj_risk,
            },
            "findings": {
                "history": history_findings,
                "current_tree": tree_findings,
                "powershell_crosscheck": ps_findings,
                "semgrep_sast": semgrep_findings,
                "injection_attacks": injection_findings,
            },
        }
        with open("report.json", "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2)
    except Exception:
        pass

    view_findings_menu(findings, state)


def run_tui_snippet_scan(state: dict) -> None:
    from ..detectors import init_presidio_analyzer, scan_snippet
    from ..reporters.base import flatten_findings
    from ..utils.git import load_secretsignore

    clear_screen()
    print("\033[1;36m============================================================\033[0m")
    print("\033[1;36m  SCAN TEXT SNIPPET\033[0m")
    print("\033[1;36m============================================================\033[0m")
    print("Paste or type your text below.")
    print("Type 'DONE' on a new line and press Enter (or Ctrl+D on Unix / Ctrl+Z on Windows).\n")

    lines: list[str] = []
    try:
        while True:
            line = input()
            if line.strip() == "DONE":
                break
            lines.append(line)
    except (EOFError, KeyboardInterrupt):
        pass

    content = "\n".join(lines)
    if not content.strip():
        return

    clear_screen()
    print("Scanning text snippet...")

    presidio_analyzer = None
    if state.get("presidio", False):
        presidio_analyzer = init_presidio_analyzer(quiet=True)

    _, ignore_tokens = load_secretsignore(state["repo_dir"])
    snippet_findings = scan_snippet(
        content,
        "text_snippet",
        entropy_threshold=state["entropy_threshold"],
        ignore_tokens=ignore_tokens,
        extract_code_blocks=state["extract_code_blocks"],
        sensitive_words=state["sensitive_words"],
        presidio_analyzer=presidio_analyzer,
    )

    history_findings = {
        "secrets": snippet_findings["secrets"],
        "pii": snippet_findings["pii"],
        "entropy": snippet_findings["entropy"],
        "commits": [],
    }
    tree_findings: dict[str, list] = {"suspicious_files": [], "current_secrets": [], "nlp_pii": []}
    findings = flatten_findings(history_findings, tree_findings, [])
    view_findings_menu(findings, state, snippet_content=content)


def run_tui_load_report(state: dict) -> None:
    from ..reporters.base import flatten_findings

    clear_screen()
    report_file = "report.json"
    if not os.path.exists(report_file):
        print("\033[1;31mError: No report.json found in the working directory.\033[0m")
        print("Please run a repository scan first to generate a report.")
        print("\nPress any key to return to Main Menu...")
        get_key()
        return

    try:
        with open(report_file, encoding="utf-8") as fp:
            report = json.load(fp)

        history_findings = report.get("findings", {}).get("history", {})
        tree_findings = report.get("findings", {}).get("current_tree", {})
        ps_findings = report.get("findings", {}).get("powershell_crosscheck", [])
        findings = flatten_findings(history_findings, tree_findings, ps_findings)
        view_findings_menu(findings, state)
    except Exception as exc:
        print(f"\033[1;31mError loading report.json: {exc}\033[0m")
        print("\nPress any key to return to Main Menu...")
        get_key()


def run_tui_redact_file(state: dict) -> None:
    from ..utils.redaction import redact_file_in_place

    clear_screen()
    print("\033[1;36m============================================================\033[0m")
    print("\033[1;36m  REDACT LOCAL FILE\033[0m")
    print("\033[1;36m============================================================\033[0m")
    filepath = input("Enter path to file you want to redact (or press Enter to cancel): ").strip()
    if not filepath:
        return

    clear_screen()
    print(f"Redacting file {filepath}...")
    success = redact_file_in_place(filepath, state["sensitive_words"])
    if success:
        print("\n\033[1;32mRedaction completed successfully!\033[0m")
    else:
        print("\n\033[1;31mRedaction failed. Please check file path and size.\033[0m")

    print("\nPress any key to return to Main Menu...")
    get_key()


# ---------------------------------------------------------------------------
# Main TUI entry point
# ---------------------------------------------------------------------------


def run_tui(args) -> None:
    """Launch the interactive TUI, initialised from parsed CLI *args*."""
    state = {
        "mask": args.mask,
        "entropy_threshold": args.entropy_threshold,
        "context_lines": args.context_lines if args.context_lines > 0 else 2,
        "sensitive_words": (
            [w.strip() for w in args.sensitive_words.split(",") if w.strip()]
            if args.sensitive_words
            else []
        ),
        "repo_dir": os.getcwd(),
        "extract_code_blocks": args.extract_code_blocks,
        "nlp_pii": args.nlp_pii,
        "ps_crosscheck": args.ps_crosscheck,
        "reflog": args.reflog,
        "since": args.since,
        "submodules": args.submodules,
        "presidio": args.presidio,
        "semgrep": args.semgrep,
    }

    selected = 0
    options = [
        "Scan Current Repository",
        "Scan Text Snippet",
        "View Last Report (report.json)",
        "Redact Local File",
        "Configure Settings",
        "Exit",
    ]

    while True:
        menu_picker("OMNI-SECRET-SCANNER TUI", options, selected)
        key = get_key()
        if key == "up":
            selected = (selected - 1) % len(options)
        elif key == "down":
            selected = (selected + 1) % len(options)
        elif key in ("escape", "ctrl-c"):
            clear_screen()
            print("Exiting...")
            break
        elif key == "enter":
            if selected == 0:
                run_tui_repo_scan(state)
            elif selected == 1:
                run_tui_snippet_scan(state)
            elif selected == 2:
                run_tui_load_report(state)
            elif selected == 3:
                run_tui_redact_file(state)
            elif selected == 4:
                configure_settings_menu(state)
            elif selected == 5:
                clear_screen()
                print("Exiting...")
                break
