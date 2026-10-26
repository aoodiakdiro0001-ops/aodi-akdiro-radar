"""Append-only receipts ledger with a sha256 seal chain (prev-hash binding).

Thread-safe as of v1.1: one RLock guards every connection operation so the
concurrent runner may fill the same chain from several workers without ever
tearing a row. Rewriting any historical row breaks the chain, `verify()`
pinpoints the exact forged index.
"""
import hashlib
import json
import sqlite3
import threading
import time

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger (
  idx INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  kind TEXT NOT NULL,
  data TEXT NOT NULL,
  prev TEXT NOT NULL,
  hash TEXT NOT NULL
);
"""

GENESIS = "GENESIS"


def _link_hash(kind, data, prev):
    payload = json.dumps({"kind": kind, "data": data, "prev": prev},
                         sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Ledger(object):
    def __init__(self, path):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.RLock()
        with self.lock:
            self.conn.executescript(_SCHEMA)

    # ------------------------------------------------------------ append
    def append(self, kind, data):
        with self.lock:
            row = self.conn.execute(
                "SELECT hash FROM ledger ORDER BY idx DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS
            data_json = json.dumps(data, sort_keys=True, ensure_ascii=False)
            mh = _link_hash(kind, data, prev)
            with self.conn:
                self.conn.execute(
                    "INSERT INTO ledger (ts, kind, data, prev, hash) VALUES (?,?,?,?,?)",
                    (time.time(), kind, data_json, prev, mh))
        return mh

    # ------------------------------------------------------------ reads
    def count(self):
        with self.lock:
            return self.conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0]

    def kinds(self):
        with self.lock:
            rows = self.conn.execute(
                "SELECT kind, COUNT(*) FROM ledger GROUP BY kind ORDER BY kind")
            return {k: n for k, n in rows}

    def findings(self):
        with self.lock:
            rows = self.conn.execute(
                "SELECT data FROM ledger WHERE kind='finding' ORDER BY idx")
            return [json.loads(dj) for (dj,) in rows]

    def rows(self):
        with self.lock:
            return self.conn.execute(
                "SELECT idx, ts, kind, data, prev, hash FROM ledger ORDER BY idx"
            ).fetchall()

    def verify(self):
        with self.lock:
            prev = GENESIS
            for idx, ts, kind, data, lprev, lhash in self.conn.execute(
                    "SELECT idx, ts, kind, data, prev, hash FROM ledger ORDER BY idx"):
                if lprev != prev:
                    return {"ok": False, "broken_at_idx": idx, "rows": self.count()}
                try:
                    want = _link_hash(kind, json.loads(data), lprev)
                except ValueError:
                    return {"ok": False, "broken_at_idx": idx, "rows": self.count()}
                if want != lhash:
                    return {"ok": False, "broken_at_idx": idx, "rows": self.count()}
                prev = lhash
            return {"ok": True, "rows": self.count()}

    def close(self):
        with self.lock:
            self.conn.close()
