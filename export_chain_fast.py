#!/usr/bin/env python3
"""
export_chain_fast.py — concurrent version of export_chain.py.

Reuses export_chain.py's rpc/other/parse_extra/outputs_of/write_record
verbatim (imported, not copied): only the fetch loop is parallelized with
a sliding window of worker threads, results written strictly in height
order. Output must be byte-identical to export_chain.py on the same range
(verified by diff before first real use).

Usage: python3 export_chain_fast.py --rpc http://127.0.0.1:38081 \
           --from 0 --to -1 --out chain.bin [--workers 16]
"""
import argparse, collections, json, time
from concurrent.futures import ThreadPoolExecutor
import export_chain as ec

def with_retry(fn, *args, tries=6):
    """RPC with exponential backoff; the daemon may reset connections
    under concurrent load."""
    for attempt in range(tries):
        try:
            return fn(*args)
        except Exception:
            if attempt == tries - 1:
                raise
            time.sleep(0.5 * 2 ** attempt)

def fetch_block(url, h):
    """Fetch one block; return list of (pub, outs) in canonical tx order."""
    blk = with_retry(ec.rpc, url, "get_block", {"height": h})
    bj = json.loads(blk["json"])
    txs = [bj["miner_tx"]]
    hashes = bj.get("tx_hashes", [])
    for off in range(0, len(hashes), 100):
        r = with_retry(ec.other, url, "/get_transactions",
                       {"txs_hashes": hashes[off:off+100],
                        "decode_as_json": True})
        for t in r.get("txs", []):
            txs.append(json.loads(t["as_json"]))
    recs = []
    for tj in txs:
        pub, addl = ec.parse_extra(tj.get("extra", []))
        outs = list(ec.outputs_of(tj))
        recs.append((pub, addl, outs))
    return recs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default="http://127.0.0.1:38081")
    ap.add_argument("--from", dest="h0", type=int, default=0)
    ap.add_argument("--to", dest="h1", type=int, default=-1)
    ap.add_argument("--out", default="chain.bin")
    ap.add_argument("--workers", type=int, default=16)
    a = ap.parse_args()

    tip = ec.rpc(a.rpc, "get_block_count", {})["count"] - 1
    h1 = tip if a.h1 < 0 else min(a.h1, tip)
    print(f"exporting heights {a.h0}..{h1} (tip {tip}) -> {a.out}, "
          f"{a.workers} workers")

    n_tx = n_skip = 0
    window = a.workers * 4
    with open(a.out, "wb") as f, ThreadPoolExecutor(a.workers) as pool:
        f.write(b"XMRSCAN2")
        pending = collections.deque()
        next_submit = a.h0
        for h in range(a.h0, h1 + 1):
            while next_submit <= h1 and len(pending) < window:
                pending.append(pool.submit(fetch_block, a.rpc, next_submit))
                next_submit += 1
            recs = pending.popleft().result()
            for pub, addl, outs in recs:
                if pub is None or not outs:
                    n_skip += 1
                    continue
                ec.write_record(f, h, pub, addl, outs)
                n_tx += 1
            if h % 10000 == 0:
                print(f"  height {h}, txs written {n_tx}", flush=True)
    print(f"done: {n_tx} txs written, {n_skip} skipped (no pubkey/outputs)")

if __name__ == "__main__":
    main()
