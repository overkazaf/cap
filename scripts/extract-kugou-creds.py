#!/usr/bin/env python3
"""Extract userId and token from KuGou play/download API flows captured by cap.

Usage:
    # From cap's default database:
    python3 scripts/extract-kugou-creds.py

    # From a specific database:
    python3 scripts/extract-kugou-creds.py --db /path/to/flows.db

    # JSON output (for piping to other tools):
    python3 scripts/extract-kugou-creds.py --json

    # Watch mode — poll the database for new flows:
    python3 scripts/extract-kugou-creds.py --watch
"""

import argparse
import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse


KUGOU_HOST_PATTERN = re.compile(r"kugou\.com$", re.IGNORECASE)

PLAY_DOWNLOAD_PATH_PATTERNS = [
    re.compile(r"/v\d+/url", re.IGNORECASE),
    re.compile(r"/v\d+/login", re.IGNORECASE),
    re.compile(r"/v\d+/sync/", re.IGNORECASE),
    re.compile(r"/freemode/", re.IGNORECASE),
    re.compile(r"/api/v\d+/", re.IGNORECASE),
    re.compile(r"/v\d+/update/", re.IGNORECASE),
    re.compile(r"/song/", re.IGNORECASE),
    re.compile(r"/play", re.IGNORECASE),
    re.compile(r"/download", re.IGNORECASE),
    re.compile(r"/yy/index\.php", re.IGNORECASE),
    re.compile(r"/oceanus/", re.IGNORECASE),
    re.compile(r"_us\d+_", re.IGNORECASE),
]

USERID_KEYS = {"userid", "user_id", "uid", "kugou_userid", "kugouid", "kugouid"}
TOKEN_KEYS = {"token", "access_token", "vip_token", "kugou_token"}


def default_db_path():
    return os.path.join(Path.home(), ".cap", "flows.db")


def is_kugou_host(host):
    if not host:
        return False
    host = host.split(":")[0]
    return bool(KUGOU_HOST_PATTERN.search(host))


def is_play_download_path(path, url=""):
    if not path:
        return True
    text = path + " " + url
    return any(p.search(text) for p in PLAY_DOWNLOAD_PATH_PATTERNS)


def extract_from_params(params):
    """Extract userId and token from a dict of key=value pairs."""
    result = {}
    for key, values in params.items():
        key_lower = key.lower()
        val = values[0] if isinstance(values, list) else values
        if not val or val in ("", "0", "null", "undefined"):
            continue
        if key_lower in USERID_KEYS:
            result["userId"] = val
            result["userId_key"] = key
        if key_lower in TOKEN_KEYS:
            result["token"] = val
            result["token_key"] = key
    return result


EMBEDDED_USERID_RE = re.compile(r"_us(\d{5,})_")
EMBEDDED_DFID_RE = re.compile(r"_df([a-z0-9]{10,})_")


def extract_from_url(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=False)
    result = extract_from_params(params)

    path = parsed.path
    m = EMBEDDED_USERID_RE.search(path)
    if m and "userId" not in result:
        result["userId"] = m.group(1)
        result["userId_key"] = "path:_us"
    m = EMBEDDED_DFID_RE.search(path)
    if m and "dfid" not in result:
        result["dfid"] = m.group(1)

    return result


def extract_from_body(body, content_type=""):
    if not body:
        return {}
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8")
        except UnicodeDecodeError:
            return {}

    if "json" in content_type.lower():
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                flat = {k: [str(v)] for k, v in data.items()}
                return extract_from_params(flat)
        except (json.JSONDecodeError, ValueError):
            pass

    if "form" in content_type.lower() or "=" in body:
        try:
            params = parse_qs(body, keep_blank_values=False)
            return extract_from_params(params)
        except Exception:
            pass

    return {}


def extract_from_headers(headers):
    if not headers:
        return {}
    result = {}
    for key, value in headers.items():
        key_lower = key.lower()
        if key_lower == "cookie":
            pairs = {}
            for part in value.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    pairs[k.strip()] = [v.strip()]
            found = extract_from_params(pairs)
            result.update(found)
        if key_lower in TOKEN_KEYS:
            result["token"] = value
            result["token_key"] = key
    return result


def extract_from_response(resp_body, resp_type=""):
    """Extract from response body (some APIs return token in response)."""
    if not resp_body:
        return {}
    if isinstance(resp_body, bytes):
        try:
            resp_body = resp_body.decode("utf-8")
        except UnicodeDecodeError:
            return {}

    if "json" not in (resp_type or "").lower():
        return {}

    try:
        data = json.loads(resp_body)
    except (json.JSONDecodeError, ValueError):
        return {}

    result = {}

    def walk(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                k_lower = k.lower()
                if k_lower in USERID_KEYS and v and str(v) not in ("0", "", "null"):
                    result.setdefault("userId", str(v))
                    result.setdefault("userId_key", f"resp.{prefix}{k}")
                if k_lower in TOKEN_KEYS and v and str(v) not in ("0", "", "null"):
                    result.setdefault("token", str(v))
                    result.setdefault("token_key", f"resp.{prefix}{k}")
                if isinstance(v, (dict, list)):
                    walk(v, f"{prefix}{k}.")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{prefix}[{i}].")

    walk(data)
    return result


def query_flows(db_path, since_id=None):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    query = """
        SELECT id, url, host, path, method, status,
               req_headers, req_body, req_body_type,
               resp_body, resp_body_type, timestamp
        FROM flows
        WHERE host LIKE '%kugou.com%'
    """
    params = []
    if since_id is not None:
        query += " AND rowid > ? "
        params.append(since_id)
    query += " ORDER BY rowid ASC"

    rows = cur.execute(query, params).fetchall()
    last_rowid = None
    if rows:
        last_rowid = cur.execute(
            "SELECT MAX(rowid) FROM flows WHERE host LIKE '%kugou.com%'"
        ).fetchone()[0]
    conn.close()
    return rows, last_rowid


def parse_headers_json(raw):
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}


def process_flow(row):
    url = row["url"]
    host = row["host"]
    path = row["path"]

    if not is_kugou_host(host):
        return None
    if not is_play_download_path(path, url):
        return None

    headers = parse_headers_json(row["req_headers"])
    req_body = row["req_body"]
    req_body_type = row["req_body_type"] or ""
    resp_body = row["resp_body"]
    resp_body_type = row["resp_body_type"] or ""

    creds = {}
    creds.update(extract_from_url(url))
    creds.update(extract_from_headers(headers))
    creds.update(extract_from_body(req_body, req_body_type))

    if "userId" not in creds or "token" not in creds:
        resp_creds = extract_from_response(resp_body, resp_body_type)
        if "userId" not in creds and "userId" in resp_creds:
            creds["userId"] = resp_creds["userId"]
            creds["userId_key"] = resp_creds.get("userId_key", "")
        if "token" not in creds and "token" in resp_creds:
            creds["token"] = resp_creds["token"]
            creds["token_key"] = resp_creds.get("token_key", "")

    # Also extract dfid and mid from query params
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=False)
    for key, vals in params.items():
        kl = key.lower()
        if kl == "dfid" and vals[0]:
            creds.setdefault("dfid", vals[0])
        if kl == "mid" and vals[0]:
            creds.setdefault("mid", vals[0])

    if not creds.get("userId") and not creds.get("token"):
        return None

    return {
        "flow_id": row["id"],
        "method": row["method"],
        "url": url,
        "host": host,
        "path": path,
        "status": row["status"],
        "timestamp": row["timestamp"],
        "userId": creds.get("userId", ""),
        "userId_key": creds.get("userId_key", ""),
        "token": creds.get("token", ""),
        "token_key": creds.get("token_key", ""),
        "dfid": creds.get("dfid", ""),
        "mid": creds.get("mid", ""),
    }


def print_table(results):
    if not results:
        print("No userId/token found in KuGou play/download flows.")
        return

    seen = set()
    unique = []
    for r in results:
        key = (r["userId"], r["token"])
        if key not in seen:
            seen.add(key)
            unique.append(r)

    print(f"\n{'='*70}")
    print(f"  KuGou Credentials ({len(unique)} unique pair(s) from {len(results)} flow(s))")
    print(f"{'='*70}\n")

    for i, r in enumerate(unique, 1):
        print(f"  [{i}] userId : {r['userId']}")
        print(f"      token  : {r['token']}")
        if r.get("dfid"):
            print(f"      dfid   : {r['dfid']}")
        if r.get("mid"):
            print(f"      mid    : {r['mid']}")
        print(f"      source : {r['method']} {r['host']}{r['path']}")
        print()


def print_json(results):
    seen = set()
    unique = []
    for r in results:
        key = (r["userId"], r["token"])
        if key not in seen:
            seen.add(key)
            unique.append(r)

    json.dump(unique, sys.stdout, ensure_ascii=False, indent=2)
    print()


def main():
    parser = argparse.ArgumentParser(description="Extract KuGou userId/token from cap flows")
    parser.add_argument("--db", default="", help="cap database path (default: ~/.cap/flows.db)")
    parser.add_argument("--json", action="store_true", help="output as JSON")
    parser.add_argument("--watch", action="store_true", help="watch for new flows (poll every 2s)")
    args = parser.parse_args()

    db_path = args.db or default_db_path()
    if not os.path.exists(db_path):
        print(f"Database not found: {db_path}", file=sys.stderr)
        print("Run `cap start` first to capture traffic.", file=sys.stderr)
        sys.exit(1)

    if args.watch:
        print(f"Watching {db_path} for KuGou play/download flows...")
        print("Press Ctrl+C to stop.\n")
        last_rowid = 0
        try:
            while True:
                rows, new_last = query_flows(db_path, since_id=last_rowid)
                for row in rows:
                    result = process_flow(row)
                    if result:
                        if args.json:
                            print(json.dumps(result, ensure_ascii=False))
                        else:
                            print(f"[{result['flow_id']}] userId={result['userId']}  "
                                  f"token={result['token'][:32]}...  "
                                  f"({result['method']} {result['host']}{result['path']})")
                if new_last is not None:
                    last_rowid = new_last
                time.sleep(2)
        except KeyboardInterrupt:
            print("\nStopped.")
    else:
        rows, _ = query_flows(db_path)
        results = []
        for row in rows:
            result = process_flow(row)
            if result:
                results.append(result)

        if args.json:
            print_json(results)
        else:
            print_table(results)


if __name__ == "__main__":
    main()
