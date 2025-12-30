"""
contract_analyzer.py
Bounty-grade smart contract analysis with proxy suppression,
reachability analysis, and eligibility classification.
"""

import re
from pathlib import Path

# -----------------------------
# Contract Classification
# -----------------------------

def classify_contract(source: str) -> str:
    proxy_indicators = [
        "delegatecall",
        "fallback()",
        "receive()",
        "ifAdmin",
        "_implementation",
        "upgradeTo",
        "EIP1967",
        "ADMIN_SLOT",
        "IMPLEMENTATION_SLOT",
    ]

    score = sum(1 for p in proxy_indicators if p in source)

    if score >= 3:
        return "PROXY"
    elif "library" in source.lower():
        return "LIBRARY"
    else:
        return "IMPLEMENTATION"

# -----------------------------
# Reachability Analysis
# -----------------------------

def is_user_reachable(function_src: str) -> bool:
    admin_guards = [
        "onlyOwner",
        "onlyAdmin",
        "ifAdmin",
        "msg.sender ==",
        "require(msg.sender",
    ]
    return not any(g in function_src for g in admin_guards)

# -----------------------------
# Proxy False-Positive Suppression
# -----------------------------

PROXY_FALSE_POSITIVES = [
    "delegatecall",
    "upgradeTo",
    "upgradeToAndCall",
    "changeAdmin",
    "ADMIN_SLOT",
    "IMPLEMENTATION_SLOT",
    "EIP1967",
    "assembly",
]

# -----------------------------
# Bounty Eligibility Engine
# -----------------------------

def bounty_eligibility(finding):
    if not finding["user_reachable"]:
        return "OUT_OF_SCOPE_ADMIN"

    if "once admin" in finding["impact"].lower():
        return "OUT_OF_SCOPE_ADMIN"

    if finding["type"] in [
        "reentrancy",
        "auth-bypass",
        "fund-drain",
        "unchecked-call",
    ]:
        return "BOUNTY_LIKELY"

    return "REVIEW_REQUIRED"

# -----------------------------
# Core Analyzer
# -----------------------------

def run(args):
    file_path = args.file
    if not file_path:
        print("[!] No Solidity file provided.")
        return

    try:
        source = Path(file_path).read_text()
    except Exception as e:
        print(f"[!] Failed to read file: {e}")
        return

    print("\n[+] Loading contract...")
    contract_type = classify_contract(source)

    print(f"[+] Contract type detected: {contract_type}")

    findings = []

    # -----------------------------
    # Naive Pattern Scanning (Phase 1)
    # -----------------------------

    patterns = {
        "delegatecall": "Use of delegatecall",
        "tx.origin": "tx.origin authentication",
        "call.value": "Unchecked ETH transfer",
        "selfdestruct": "Selfdestruct present",
        "upgradeTo": "Upgradeable proxy function",
    }

    functions = re.split(r"function\s+", source)

    for fn in functions[1:]:
        header, body = fn.split("{", 1)
        fn_src = body

        for p, desc in patterns.items():
            if p in fn_src:
                findings.append({
                    "type": (
                        "auth-bypass" if p == "tx.origin" else
                        "fund-drain" if p == "call.value" else
                        "proxy-mechanism" if p == "upgradeTo" else
                        "generic"
                    ),
                    "description": desc,
                    "code": p,
                    "impact": f"Potential issue involving {desc}",
                    "user_reachable": is_user_reachable(fn_src),
                })

    # -----------------------------
    # Proxy Suppression
    # -----------------------------

    if contract_type == "PROXY":
        findings = [
            f for f in findings
            if not any(fp in f["code"] for fp in PROXY_FALSE_POSITIVES)
        ]

    # -----------------------------
    # Eligibility Classification
    # -----------------------------

    for f in findings:
        f["eligibility"] = bounty_eligibility(f)

    # -----------------------------
    # Output
    # -----------------------------

    if not findings:
        print("\n[✓] No bounty-relevant issues detected.")
        print("[i] Recommendation: Skip for bug bounty.")
        return

    print("\n========== Findings ==========\n")

    bounty_count = 0
    admin_count = 0

    for f in findings:
        print(f"[!] {f['description']}")
        print(f"    Reachable by EOA: {'YES' if f['user_reachable'] else 'NO'}")
        print(f"    Bounty Eligibility: {f['eligibility']}\n")

        if f["eligibility"] == "BOUNTY_LIKELY":
            bounty_count += 1
        if f["eligibility"] == "OUT_OF_SCOPE_ADMIN":
            admin_count += 1

    # -----------------------------
    # Reviewer-Grade Summary
    # -----------------------------

    print("══════════════════════════════════════")
    print("Bounty Viability Summary")
    print("══════════════════════════════════════")
    print(f"Contract Type: {contract_type}")
    print(f"Total Findings: {len(findings)}")
    print(f"User-Reachable Issues: {bounty_count}")
    print(f"Admin/Governance Issues: {admin_count}")
    print(f"Bounty-Likely Issues: {bounty_count}")
    print("\nRecommendation:")

    if bounty_count == 0:
        print("→ Skip for bug bounty")
        if contract_type == "PROXY":
            print("→ Review implementation contract instead")
    else:
        print("→ Worth manual validation & exploit development")

    print("══════════════════════════════════════\n")
