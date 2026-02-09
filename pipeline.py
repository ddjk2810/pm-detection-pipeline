"""
Daily PM Software Detection Pipeline

Re-scans ~8,200 property management company websites to detect which PM
software platform they use (AppFolio, Yardi, Buildium, RentManager, etc.).

Chunks all domains into 8 groups (~1,025 each) and processes one chunk
per day, completing a full rotation every ~8 days.

Daily flow:
  1. Seed SQLite DB from pm_results.csv (DB is gitignored/ephemeral)
  2. Re-scan today's chunk (~1,025 domains) with --no-skip
  3. DNS recovery pass on all unknowns (CNAME + MX/TXT strategies)
  4. Export DB back to pm_results.csv
  5. Snapshot + diff if rotation completes (chunk wraps to 0)
  6. Write daily log + GitHub Issue summary

Usage:
  python pipeline.py                  # Full run (rescan chunk + recovery)
  python pipeline.py --skip-rescan    # Skip chunk re-scan
  python pipeline.py --skip-recovery  # Skip DNS recovery pass
"""

import argparse
import csv
import json
import os
import sqlite3
import subprocess
import sys
from collections import Counter
from datetime import date


PIPELINE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PIPELINE_DIR, "data")
SNAPSHOTS_DIR = os.path.join(DATA_DIR, "snapshots")
LOGS_DIR = os.path.join(DATA_DIR, "logs")

# Data files
PM_RESULTS_CSV = os.path.join(DATA_DIR, "pm_results.csv")
DOMAINS_DOORS_CSV = os.path.join(DATA_DIR, "domains_doors.csv")
PIPELINE_STATE_JSON = os.path.join(DATA_DIR, "pipeline_state.json")

# DB paths (ephemeral, seeded each run)
PM_DB_PATH = os.path.join(PIPELINE_DIR, "pm_system_results.db")
RECOVERY_DB_PATH = os.path.join(PIPELINE_DIR, "pm_recovery_results.db")

# Intermediate files (gitignored)
CHUNK_DOMAINS_CSV = os.path.join(DATA_DIR, "chunk_domains.csv")
CHUNK_RESULTS_CSV = os.path.join(DATA_DIR, "chunk_results.csv")
ROTATION_SUMMARY_PATH = os.path.join(DATA_DIR, "rotation_summary.md")

# GitHub Issue files (gitignored, read by workflow before commit)
ISSUE_SUMMARY_PATH = os.path.join(PIPELINE_DIR, "daily_summary.md")
ISSUE_TITLE_PATH = os.path.join(PIPELINE_DIR, "daily_summary_title.txt")

DETECTION_TIMEOUT = 3 * 3600  # 3 hours
RECOVERY_TIMEOUT = 30 * 60   # 30 minutes


def log(msg):
    print(f"[pipeline] {msg}", flush=True)


def read_csv(path):
    """Read a CSV file and return list of dicts."""
    if not os.path.exists(path):
        return []
    csv.field_size_limit(sys.maxsize)
    with open(path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fieldnames):
    """Write a CSV file from list of dicts."""
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run_step(cmd, cwd, timeout, step_name):
    """Run a subprocess, stream output, raise on failure."""
    log(f"Running: {' '.join(cmd)}")
    log(f"  cwd: {cwd}")
    proc = subprocess.run(cmd, cwd=cwd, timeout=timeout, capture_output=False)
    if proc.returncode != 0:
        raise RuntimeError(f"{step_name} failed with exit code {proc.returncode}")
    log(f"{step_name} completed successfully.")


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------

def load_state():
    if not os.path.exists(PIPELINE_STATE_JSON):
        return {
            "last_chunk_index": -1,
            "last_run_date": None,
            "last_snapshot_date": "2026-02-02",
            "total_chunks": 8,
        }
    with open(PIPELINE_STATE_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(state):
    with open(PIPELINE_STATE_JSON, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    log(f"State saved: chunk={state['last_chunk_index']}, date={state['last_run_date']}")


# ---------------------------------------------------------------------------
# DB seeding & export
# ---------------------------------------------------------------------------

def step_seed_db():
    """Reconstruct SQLite DB from pm_results.csv."""
    log("=" * 60)
    log("STEP: Seed database from pm_results.csv")
    log("=" * 60)

    for db in [PM_DB_PATH, RECOVERY_DB_PATH]:
        if os.path.exists(db):
            os.remove(db)

    rows = read_csv(PM_RESULTS_CSV)
    if not rows:
        log("WARNING: pm_results.csv is empty or missing")
        return 0

    conn = sqlite3.connect(PM_DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            portal_system TEXT,
            portal_subdomain TEXT,
            confidence TEXT,
            detection_method TEXT,
            validated INTEGER,
            validation_website TEXT,
            error TEXT,
            timestamp TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain ON results(domain)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_portal_system ON results(portal_system)')

    inserted = 0
    for row in rows:
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO results
                (domain, portal_system, portal_subdomain, confidence,
                 detection_method, validated, validation_website,
                 error, timestamp, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                row.get("domain", ""),
                row.get("portal_system", ""),
                row.get("portal_subdomain", ""),
                row.get("confidence", ""),
                row.get("detection_method", ""),
                int(row.get("validated", 0)),
                row.get("validation_website", ""),
                row.get("error", ""),
                row.get("timestamp", ""),
            ))
            inserted += 1
        except Exception as e:
            log(f"  Seed error for {row.get('domain', '?')}: {e}")

    conn.commit()
    conn.close()
    log(f"Seeded DB with {inserted} domains")
    return inserted


def step_export_db():
    """Export SQLite DB back to pm_results.csv."""
    log("=" * 60)
    log("STEP: Export database to pm_results.csv")
    log("=" * 60)

    if not os.path.exists(PM_DB_PATH):
        log("WARNING: No DB to export")
        return

    run_step(
        [sys.executable, "pm_system_detector.py",
         "export", PM_RESULTS_CSV,
         "--db", "pm_system_results.db"],
        cwd=PIPELINE_DIR,
        timeout=60,
        step_name="Export DB to CSV",
    )

    rows = read_csv(PM_RESULTS_CSV)
    log(f"Exported {len(rows)} domains to pm_results.csv")


def get_db_stats():
    """Get high-level DB stats."""
    if not os.path.exists(PM_DB_PATH):
        return None
    try:
        conn = sqlite3.connect(PM_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM results")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM results WHERE portal_system != 'unknown' AND portal_system NOT LIKE 'custom:%'")
        known = cursor.fetchone()[0]
        cursor.execute("SELECT portal_system, COUNT(*) FROM results GROUP BY portal_system")
        by_system = {row[0]: row[1] for row in cursor.fetchall()}
        conn.close()
        return {"total": total, "known": known, "unknown": by_system.get("unknown", 0), "by_system": by_system}
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Chunked re-scan
# ---------------------------------------------------------------------------

def get_chunk_domains(chunk_index, total_chunks):
    """Return domains for a given chunk (deterministic, alphabetically sorted)."""
    rows = read_csv(PM_RESULTS_CSV)
    all_domains = sorted(set(r.get("domain", "") for r in rows if r.get("domain")))

    chunk_size = len(all_domains) // total_chunks
    remainder = len(all_domains) % total_chunks

    start = 0
    for i in range(chunk_index):
        start += chunk_size + (1 if i < remainder else 0)
    end = start + chunk_size + (1 if chunk_index < remainder else 0)

    chunk = all_domains[start:end]
    log(f"Chunk {chunk_index}/{total_chunks}: domains {start}-{end-1} "
        f"({len(chunk)} domains, total corpus: {len(all_domains)})")
    return chunk


def step_rescan_chunk(state):
    """Re-scan one chunk of existing domains with --no-skip."""
    total_chunks = state.get("total_chunks", 8)
    chunk_index = (state["last_chunk_index"] + 1) % total_chunks

    log("=" * 60)
    log(f"STEP: Re-scan chunk {chunk_index}/{total_chunks}")
    log("=" * 60)

    domains = get_chunk_domains(chunk_index, total_chunks)
    if not domains:
        log("No domains in this chunk")
        return chunk_index, 0

    write_csv(CHUNK_DOMAINS_CSV, [{"domain": d} for d in domains], ["domain"])

    run_step(
        [sys.executable, "pm_system_detector.py",
         "batch", CHUNK_DOMAINS_CSV, CHUNK_RESULTS_CSV,
         "--db", "pm_system_results.db",
         "--no-skip"],
        cwd=PIPELINE_DIR,
        timeout=DETECTION_TIMEOUT,
        step_name=f"Re-scan Chunk {chunk_index}",
    )

    results = read_csv(CHUNK_RESULTS_CSV)
    unknowns = sum(1 for r in results if r.get("portal_system") == "unknown")
    log(f"Chunk {chunk_index} complete: {len(results)} domains "
        f"({len(results) - unknowns} detected, {unknowns} unknown)")

    return chunk_index, len(domains)


# ---------------------------------------------------------------------------
# DNS recovery
# ---------------------------------------------------------------------------

def step_dns_recovery():
    """Run DNS-based recovery on unknown domains."""
    log("=" * 60)
    log("STEP: DNS recovery for unknown domains")
    log("=" * 60)

    if not os.path.exists(PM_DB_PATH):
        log("No DB found — skipping")
        return 0

    conn = sqlite3.connect(PM_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM results WHERE portal_system = 'unknown'")
    unknowns = cursor.fetchone()[0]
    conn.close()

    if unknowns == 0:
        log("No unknown domains — skipping")
        return 0

    log(f"Found {unknowns} unknown domains, running DNS recovery (strategies 2,6)")

    run_step(
        [sys.executable, "pm_unknown_recovery.py",
         "run", "--strategies", "2,6",
         "--main-db", "pm_system_results.db",
         "--db", "pm_recovery_results.db"],
        cwd=PIPELINE_DIR,
        timeout=RECOVERY_TIMEOUT,
        step_name="DNS Recovery",
    )

    run_step(
        [sys.executable, "pm_unknown_recovery.py",
         "consolidate",
         "--main-db", "pm_system_results.db",
         "--db", "pm_recovery_results.db"],
        cwd=PIPELINE_DIR,
        timeout=60,
        step_name="Consolidate Recovery",
    )

    conn = sqlite3.connect(PM_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM results WHERE portal_system = 'unknown'")
    new_unknowns = cursor.fetchone()[0]
    conn.close()

    recovered = unknowns - new_unknowns
    log(f"DNS recovery: {recovered} recovered ({new_unknowns} still unknown)")
    return recovered


# ---------------------------------------------------------------------------
# Snapshot & diff on rotation completion
# ---------------------------------------------------------------------------

def step_snapshot_if_rotation_complete(chunk_index, state):
    """Take a snapshot and diff when chunk rotation wraps to 0."""
    if chunk_index != 0:
        return False
    if state.get("last_chunk_index", -1) == -1:
        log("First rotation starting — skipping snapshot")
        return False

    log("=" * 60)
    log("STEP: Full rotation complete — snapshot and diff")
    log("=" * 60)

    today = date.today().isoformat()
    os.makedirs(SNAPSHOTS_DIR, exist_ok=True)
    snapshot_path = os.path.join(SNAPSHOTS_DIR, f"snapshot_{today}.csv")

    run_step(
        [sys.executable, "pm_system_detector.py",
         "snapshot", snapshot_path,
         "--db", "pm_system_results.db"],
        cwd=PIPELINE_DIR,
        timeout=60,
        step_name="Take Snapshot",
    )

    prev_date = state.get("last_snapshot_date", "2026-02-02")
    prev_snapshot = os.path.join(SNAPSHOTS_DIR, f"snapshot_{prev_date}_clean.csv")
    if not os.path.exists(prev_snapshot):
        prev_snapshot = os.path.join(SNAPSHOTS_DIR, f"snapshot_{prev_date}.csv")

    if os.path.exists(prev_snapshot):
        log(f"Diffing against: {prev_snapshot}")
        diff_csv = os.path.join(SNAPSHOTS_DIR, f"diff_{prev_date}_to_{today}.csv")
        proc = subprocess.run(
            [sys.executable, "pm_system_detector.py",
             "diff", prev_snapshot,
             "--db", "pm_system_results.db",
             "--output", diff_csv],
            cwd=PIPELINE_DIR, timeout=60,
            capture_output=True, text=True,
        )
        _write_rotation_summary(today, prev_date, proc.stdout or "", diff_csv)
    else:
        log(f"No previous snapshot at {prev_snapshot} — skipping diff")

    state["last_snapshot_date"] = today
    log(f"Snapshot saved: {snapshot_path}")
    return True


def _write_rotation_summary(today, prev_date, diff_report, diff_csv_path):
    """Write markdown rotation report for GitHub Issue."""
    changes = read_csv(diff_csv_path) if os.path.exists(diff_csv_path) else []
    switches = [c for c in changes if c.get("change_type") == "switch"]
    new_detections = [c for c in changes if c.get("change_type") == "new_detection"]
    lost_detections = [c for c in changes if c.get("change_type") == "lost_detection"]

    lines = [
        f"## PM Software Detection - Full Rotation Report",
        f"",
        f"**Period:** {prev_date} to {today}",
        f"**Changes detected:** {len(changes)}",
        f"",
        f"### Summary",
        f"- PM system switches: {len(switches)}",
        f"- New detections (unknown -> known): {len(new_detections)}",
        f"- Lost detections (known -> unknown): {len(lost_detections)}",
        f"",
    ]

    if switches:
        lines.append("### PM System Switches")
        lines.append("| Domain | Doors | From | To |")
        lines.append("|--------|-------|------|----|")
        for s in sorted(switches, key=lambda x: -int(x.get("doors", 0) or 0))[:20]:
            lines.append(f"| {s['domain']} | {s.get('doors', '?')} | {s['previous']} | {s['current']} |")
        if len(switches) > 20:
            lines.append(f"| ... | | | ({len(switches) - 20} more) |")
        lines.append("")

    if new_detections:
        lines.append("### New Detections")
        lines.append("| Domain | Doors | Detected As |")
        lines.append("|--------|-------|-------------|")
        for s in sorted(new_detections, key=lambda x: -int(x.get("doors", 0) or 0))[:20]:
            lines.append(f"| {s['domain']} | {s.get('doors', '?')} | {s['current']} |")
        if len(new_detections) > 20:
            lines.append(f"| ... | | ({len(new_detections) - 20} more) |")
        lines.append("")

    if lost_detections:
        lines.append("### Lost Detections")
        lines.append("| Domain | Doors | Was |")
        lines.append("|--------|-------|-----|")
        for s in sorted(lost_detections, key=lambda x: -int(x.get("doors", 0) or 0))[:20]:
            lines.append(f"| {s['domain']} | {s.get('doors', '?')} | {s['previous']} |")
        if len(lost_detections) > 20:
            lines.append(f"| ... | | ({len(lost_detections) - 20} more) |")
        lines.append("")

    lines.append("<details><summary>Full diff report</summary>")
    lines.append("")
    lines.append("```")
    lines.append(diff_report.strip())
    lines.append("```")
    lines.append("</details>")

    with open(ROTATION_SUMMARY_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log(f"Wrote rotation summary: {ROTATION_SUMMARY_PATH}")


# ---------------------------------------------------------------------------
# Logging & GitHub Issue
# ---------------------------------------------------------------------------

def step_log(chunk_info, db_stats):
    """Write daily log and GitHub Issue summary."""
    log("=" * 60)
    log("STEP: Generate daily log")
    log("=" * 60)

    today = date.today().isoformat()
    os.makedirs(LOGS_DIR, exist_ok=True)

    # --- Plain text log ---
    log_path = os.path.join(LOGS_DIR, f"daily_{today}.txt")
    lines = [
        f"PM Detection Pipeline: {today}",
        "=" * 60,
    ]

    if chunk_info:
        lines.extend([
            "",
            "CHUNK RE-SCAN",
            "-" * 40,
            f"Chunk: {chunk_info['chunk_index']}/{chunk_info['total_chunks']}",
            f"Domains re-scanned: {chunk_info['domains_rescanned']}",
            f"DNS recovered: {chunk_info.get('dns_recovered', 0)}",
            f"Rotation complete: {'Yes' if chunk_info.get('rotation_complete') else 'No'}",
        ])

    if db_stats:
        detection_rate = round(100 * db_stats["known"] / db_stats["total"], 1) if db_stats["total"] else 0
        lines.extend([
            "",
            "DATABASE SUMMARY",
            "-" * 40,
            f"Total domains: {db_stats['total']:,}",
            f"Detected (known PM): {db_stats['known']:,} ({detection_rate}%)",
            f"Unknown: {db_stats['unknown']:,}",
            "",
            "Market share:",
        ])
        for system, count in sorted(db_stats["by_system"].items(), key=lambda x: -x[1]):
            if system != "unknown" and not system.startswith("custom:"):
                lines.append(f"  {system}: {count:,}")

    log_text = "\n".join(lines) + "\n"
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(log_text)
    log(f"Wrote log: {log_path}")
    print()
    print(log_text)

    # --- GitHub Issue markdown ---
    _write_issue_summary(today, chunk_info, db_stats)

    return log_path


def _write_issue_summary(today, chunk_info, db_stats):
    """Write GitHub Issue markdown summary + title file."""
    parts = [f"PM Detection: {today}"]
    if chunk_info:
        parts.append(f"chunk {chunk_info['chunk_index']}/{chunk_info['total_chunks']}")
    if chunk_info and chunk_info.get("rotation_complete"):
        parts.append("ROTATION COMPLETE")
    title = " - ".join(parts)

    with open(ISSUE_TITLE_PATH, "w", encoding="utf-8") as f:
        f.write(title)

    lines = []

    if chunk_info:
        idx = chunk_info["chunk_index"]
        total = chunk_info["total_chunks"]
        rescanned = chunk_info["domains_rescanned"]
        recovered = chunk_info.get("dns_recovered", 0)
        rotation = chunk_info.get("rotation_complete", False)

        progress = "".join(
            ":green_square:" if i < idx else
            ":blue_square:" if i == idx else
            ":white_large_square:"
            for i in range(total)
        )
        lines.append("### Chunk Re-scan")
        lines.append(f"{progress} **{idx}/{total}**")
        lines.append(f"- Domains re-scanned: **{rescanned:,}**")
        lines.append(f"- DNS recovered: **{recovered}**")
        if rotation:
            lines.append("- :tada: **Full rotation complete** — snapshot & diff generated")
        lines.append("")

    if db_stats:
        total_domains = db_stats["total"]
        known = db_stats["known"]
        unknown = db_stats["unknown"]
        detection_rate = round(100 * known / total_domains, 1) if total_domains else 0

        lines.append("### Database Summary")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total domains | {total_domains:,} |")
        lines.append(f"| Detected (known PM) | {known:,} ({detection_rate}%) |")
        lines.append(f"| Unknown | {unknown:,} |")

        by_system = db_stats.get("by_system", {})
        if by_system:
            lines.append("")
            lines.append("**Market share:**")
            lines.append("| PM System | Count |")
            lines.append("|-----------|-------|")
            for system, count in sorted(by_system.items(), key=lambda x: -x[1]):
                if system != "unknown" and not system.startswith("custom:"):
                    lines.append(f"| {system} | {count:,} |")
        lines.append("")

    with open(ISSUE_SUMMARY_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log(f"Wrote issue summary: {ISSUE_SUMMARY_PATH}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Daily PM Software Detection Pipeline")
    parser.add_argument("--skip-rescan", action="store_true", help="Skip chunk re-scan")
    parser.add_argument("--skip-recovery", action="store_true", help="Skip DNS recovery pass")
    args = parser.parse_args()

    today = date.today()
    today_str = today.isoformat()

    log(f"Pipeline started: {today_str} ({today.strftime('%A')})")
    log(f"Pipeline dir: {PIPELINE_DIR}")

    # 1. Load state
    state = load_state()
    log(f"State: chunk={state['last_chunk_index']}, "
        f"last_run={state['last_run_date']}, chunks={state['total_chunks']}")

    # 2. Seed DB from CSV
    step_seed_db()

    # 3. Re-scan today's chunk
    chunk_index = None
    domains_rescanned = 0
    if not args.skip_rescan:
        chunk_index, domains_rescanned = step_rescan_chunk(state)
    else:
        log("Skipping chunk re-scan (--skip-rescan)")

    # 4. DNS recovery
    dns_recovered = 0
    if not args.skip_recovery:
        dns_recovered = step_dns_recovery()
    else:
        log("Skipping DNS recovery (--skip-recovery)")

    # 5. Export DB back to CSV
    step_export_db()

    # 6. Snapshot/diff if rotation complete
    rotation_complete = False
    if chunk_index is not None:
        rotation_complete = step_snapshot_if_rotation_complete(chunk_index, state)

    # 7. Log + Issue summary
    chunk_info = None
    if chunk_index is not None:
        chunk_info = {
            "chunk_index": chunk_index,
            "total_chunks": state["total_chunks"],
            "domains_rescanned": domains_rescanned,
            "dns_recovered": dns_recovered,
            "rotation_complete": rotation_complete,
        }

    db_stats = get_db_stats()
    step_log(chunk_info, db_stats)

    # 8. Save state
    if chunk_index is not None:
        state["last_chunk_index"] = chunk_index
    state["last_run_date"] = today_str
    save_state(state)

    # Clean up intermediates
    for f in [CHUNK_DOMAINS_CSV, CHUNK_RESULTS_CSV]:
        if os.path.exists(f):
            os.remove(f)

    log("Pipeline complete!")


if __name__ == "__main__":
    main()
