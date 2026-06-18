# Security policy

## Scope and trust model

This is an offline scanner. It reads a blockchain export and a wallet's
**private view key** + **public spend key**, and reports which outputs the
wallet owns. It does **not**:

- handle spend keys or seed phrases,
- sign, build, or broadcast transactions,
- talk to the network (it consumes data a node already produced).

A view key is watch-only: the worst an attacker who obtains it can do is *see*
incoming transactions to that wallet — it cannot move funds. Still, treat real
view keys as sensitive and run the tool on a machine you trust.

The security-critical property of this project is **correctness**: the GPU
result must equal Monero's reference math exactly. A scanner that misses or
misattributes an output is the bug class that matters most here.

## Reporting a vulnerability

Please **do not** open a public issue for a security problem (e.g. a case where
the GPU and CPU scanners disagree on real data, or any memory-safety issue in
the parsers/kernels).

Use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on this repository.

Include the input that triggers it (a minimal `XMRSCAN1` fixture is ideal) and
the expected vs actual owned-set. Reproductions that make `make gputest` fail
are the gold standard.
