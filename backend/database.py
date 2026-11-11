"""
database.py — Persistent SQLite Store for AutoRepo PR Reviews & Vulnerability Ledger
"""

import os
import json
import time
import uuid
import sqlite3
from typing import Dict, List, Any, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "autorepo.db")

PRESET_PR_SCENARIOS = [
    {
        "scenario_id": "pr_payment_sqli",
        "pr_number": 142,
        "pr_title": "feat(payments): add customer invoice lookup and batch ledger sync",
        "file_path": "services/payment_ledger.py",
        "author": "dev-checkout-team",
        "branch": "feat/payment-sync -> main",
        "code": (
            "import sqlite3\n"
            "import hashlib\n\n"
            "# Hardcoded payment gateway secret key (CWE-798 demo)\n"
            "api_secret_token = \"PAYMENT_VAULT_SECRET_9988776655443322\"\n\n"
            "def fetch_user_invoices(cursor, user_id, audit_trail=[]):\n"
            "    # Vulnerable unparameterized f-string SQL query\n"
            "    query = f\"SELECT * FROM accounts WHERE user_id = '{user_id}' AND active = 1\"\n"
            "    cursor.execute(query)\n"
            "    rows = cursor.fetchall()\n"
            "    audit_trail.append(user_id)\n"
            "    return rows\n\n"
            "def sync_merchant_settlements(db_conn, merchant_ids, transactions):\n"
            "    settled = []\n"
            "    # O(N^2) nested loop + N+1 database query inside loop\n"
            "    for m_id in merchant_ids:\n"
            "        for tx in transactions:\n"
            "            if tx['merchant_id'] == m_id and tx['amount'] > 0:\n"
            "                db_conn.execute(f\"UPDATE ledger SET status='PAID' WHERE tx_id={tx['id']}\")\n"
            "                settled.append(tx['id'])\n"
            "    return settled\n"
        )
    },
    {
        "scenario_id": "pr_webhook_rce",
        "pr_number": 189,
        "pr_title": "chore(webhooks): parse dynamic rule expressions and session signatures",
        "file_path": "workers/webhook_evaluator.py",
        "author": "platform-integrations",
        "branch": "chore/webhook-eval -> main",
        "code": (
            "import os\n"
            "import pickle\n"
            "import hashlib\n\n"
            "def evaluate_Routing_Rule(raw_expression, payload_bytes):\n"
            "    try:\n"
            "        # Critical RCE via eval() and unsafe pickle deserialization\n"
            "        session_obj = pickle.loads(payload_bytes)\n"
            "        result = eval(raw_expression)\n"
            "        sig = hashlib.md5(raw_expression.encode()).hexdigest()\n"
            "        return {\"result\": result, \"sig\": sig, \"session\": session_obj}\n"
            "    except:\n"
            "        return None\n"
        )
    },
    {
        "scenario_id": "pr_clean_approved",
        "pr_number": 215,
        "pr_title": "refactor(auth): harden token-bucket rate limiter with type annotations",
        "file_path": "core/token_bucket.py",
        "author": "sanath-s-gowda",
        "branch": "refactor/hardened-limiter -> main",
        "code": (
            "import time\n"
            "import hmac\n"
            "import hashlib\n"
            "from typing import Tuple, Dict\n\n"
            "def verify_webhook_signature(payload: bytes, secret: str, signature_header: str) -> bool:\n"
            "    \"\"\"Verifies GitHub X-Hub-Signature-256 using constant-time HMAC-SHA256.\"\"\"\n"
            "    expected = \"sha256=\" + hmac.new(secret.encode(\"utf-8\"), payload, hashlib.sha256).hexdigest()\n"
            "    return hmac.compare_digest(expected, signature_header)\n\n"
            "def compute_token_refill(current_tokens: float, capacity: float, elapsed_sec: float, rate: float) -> float:\n"
            "    \"\"\"Computes O(1) deterministic token bucket refill balance.\"\"\"\n"
            "    if elapsed_sec <= 0:\n"
            "        return current_tokens\n"
            "    return min(capacity, current_tokens + (elapsed_sec * rate))\n"
        )
    }
]


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pr_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            review_id TEXT UNIQUE,
            timestamp REAL,
            pr_title TEXT,
            file_path TEXT,
            score INTEGER,
            verdict TEXT,
            security_count INTEGER,
            arch_count INTEGER,
            test_count INTEGER,
            avg_complexity REAL,
            worst_big_o TEXT,
            latency_ms REAL,
            full_report_json TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_review_report(report: Dict[str, Any]) -> str:
    review_id = f"rev_{uuid.uuid4().hex[:10]}"
    report["review_id"] = review_id
    report["timestamp"] = time.time()

    conn = get_conn()
    conn.execute("""
        INSERT INTO pr_reviews (
            review_id, timestamp, pr_title, file_path, score, verdict,
            security_count, arch_count, test_count, avg_complexity,
            worst_big_o, latency_ms, full_report_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        review_id,
        report["timestamp"],
        report["pr_title"],
        report["file_path"],
        report["score"],
        report["verdict"],
        len(report["security_findings"]),
        len(report["arch_findings"]),
        len(report["test_cases_meta"]),
        report["ast_report"]["avg_cyclomatic_complexity"],
        report["ast_report"]["worst_time_complexity"],
        report["total_latency_ms"],
        json.dumps(report)
    ))
    conn.commit()
    conn.close()
    return review_id


def get_review_history(limit: int = 25) -> List[Dict[str, Any]]:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT review_id, timestamp, pr_title, file_path, score, verdict,
               security_count, arch_count, test_count, avg_complexity, worst_big_o, latency_ms
        FROM pr_reviews
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_review_by_id(review_id: str) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT full_report_json FROM pr_reviews WHERE review_id = ?", (review_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return json.loads(row["full_report_json"])


def get_aggregate_stats() -> Dict[str, Any]:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*), AVG(score), SUM(security_count), SUM(arch_count), SUM(test_count) FROM pr_reviews")
    row = cursor.fetchone()
    conn.close()
    return {
        "total_prs_reviewed": row[0] or 0,
        "avg_readiness_score": round(row[1] or 0.0, 1),
        "total_cwe_caught": row[2] or 0,
        "total_ast_smells": row[3] or 0,
        "total_tests_synthesized": row[4] or 0
    }


init_db()
