#!/usr/bin/env python3
"""
export_chain.py - export (tx pubkey, output keys, view tags) from monerod
into an XMRSCAN1 flat file for scan_cpu / the GPU kernel.

Usage:
  python3 export_chain.py --rpc http://127.0.0.1:38081 \
      --from 0 --to 50000 --out chain.bin

(38081 = stagenet RPC port; mainnet is 18081.)

Record format (little-endian):
  magic "XMRSCAN1"
  then per tx: u32 height | u8 n_out | R[32] | n_out*( key[32] | vt_flag u8 | vt u8 )

Notes:
- includes coinbase (miner) txs.
- txs without a parsable tx pubkey in extra are skipped (can't be scanned).
- only the first 255 outputs of a tx are recorded (format limit; real txs
  are far below this).
"""
import argparse, json, struct, sys, urllib.request

def rpc(url, method, params):
    req = urllib.request.Request(
        url + "/json_rpc",
        json.dumps({"jsonrpc": "2.0", "id": "0", "method": method,
                    "params": params}).encode(),
        {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        resp = json.load(r)
    if "error" in resp:
        raise RuntimeError(f"{method}: {resp['error']}")
    return resp["result"]

def other(url, path, body):
    req = urllib.request.Request(
        url + path, json.dumps(body).encode(),
        {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)

def parse_extra(extra_bytes):
    """Return tx pubkey (32 bytes) or None. Tags per cryptonote_basic:
    0x00 padding, 0x01 pubkey, 0x02 nonce, 0x03 merge-mining, 0x04 additional
    pubkeys, 0xDE minergate. Stop on unknown tag."""
    b = bytes(extra_bytes)
    i, pub = 0, None
    def varint(i):
        v = s = 0
        while True:
            c = b[i]; i += 1
            v |= (c & 0x7F) << s
            if not c & 0x80: return v, i
            s += 7
    while i < len(b):
        tag = b[i]; i += 1
        if tag == 0x00:                       # padding: zeros to end
            break
        elif tag == 0x01:
            if i + 32 > len(b): break
            if pub is None: pub = b[i:i+32]
            i += 32
        elif tag == 0x02:
            if i >= len(b): break
            n = b[i]; i += 1 + n
        elif tag == 0x03:
            try:
                _, i = varint(i)              # depth
                i += 32                       # merkle root
            except IndexError: break
        elif tag == 0x04:
            try:
                n, i = varint(i)
                i += 32 * n
            except IndexError: break
        else:
            break                             # unknown tag: stop parsing
    return pub

def outputs_of(tx_json):
    """Yield (key32, vt_flag, vt) per vout entry."""
    for v in tx_json.get("vout", []):
        tgt = v.get("target", {})
        if "tagged_key" in tgt:
            tk = tgt["tagged_key"]
            yield bytes.fromhex(tk["key"]), 1, int(tk["view_tag"], 16)
        elif "key" in tgt:
            yield bytes.fromhex(tgt["key"]), 0, 0
        # other target types (rare/none on modern chain) are skipped

def write_record(f, height, pub, outs):
    outs = outs[:255]
    f.write(struct.pack("<IB", height, len(outs)))
    f.write(pub)
    for key, flag, vt in outs:
        f.write(key + bytes([flag, vt]))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default="http://127.0.0.1:38081")
    ap.add_argument("--from", dest="h0", type=int, default=0)
    ap.add_argument("--to", dest="h1", type=int, default=-1)
    ap.add_argument("--out", default="chain.bin")
    a = ap.parse_args()

    tip = rpc(a.rpc, "get_block_count", {})["count"] - 1
    h1 = tip if a.h1 < 0 else min(a.h1, tip)
    print(f"exporting heights {a.h0}..{h1} (tip {tip}) -> {a.out}")

    n_tx = n_skip = 0
    with open(a.out, "wb") as f:
        f.write(b"XMRSCAN1")
        for h in range(a.h0, h1 + 1):
            blk = rpc(a.rpc, "get_block", {"height": h})
            bj = json.loads(blk["json"])
            txs = []                          # (height, tx_json)
            txs.append(bj["miner_tx"])
            hashes = bj.get("tx_hashes", [])
            for off in range(0, len(hashes), 100):
                r = other(a.rpc, "/get_transactions",
                          {"txs_hashes": hashes[off:off+100],
                           "decode_as_json": True})
                for t in r.get("txs", []):
                    txs.append(json.loads(t["as_json"]))
            for tj in txs:
                pub = parse_extra(tj.get("extra", []))
                outs = list(outputs_of(tj))
                if pub is None or not outs:
                    n_skip += 1
                    continue
                write_record(f, h, pub, outs)
                n_tx += 1
            if h % 1000 == 0:
                print(f"  height {h}, txs written {n_tx}", flush=True)
    print(f"done: {n_tx} txs written, {n_skip} skipped (no pubkey/outputs)")

if __name__ == "__main__":
    main()
