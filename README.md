# macOS XOR proxy (PF-compatible)

This repository ports the idea of [`ipt_xor`](https://github.com/faicker/ipt_xor/) to macOS without requiring a kernel extension. Instead of an iptables target, it provides a small user-space proxy that XOR-obfuscates traffic diverted to it by the built-in PF firewall.

## Overview

`src/xor_proxy.py` implements a TCP/UDP proxy that applies a configurable XOR key to all data flowing through it. By pairing the proxy with PF `rdr` rules, you can transparently obfuscate traffic between a client and an upstream server in the same spirit as the original `ipt_xor` target.

The proxy works symmetrically: data from the client to the upstream host is XOR'ed with the provided key and data from the upstream host back to the client is XOR'ed with the same key.

## Requirements

- macOS with Python 3.10+ (tested on Monterey and newer)
- PF enabled (it is on by default) and permissions to load rules via `pfctl`

## Usage

1. Start the proxy locally on a chosen port. Example for TCP port 8080 forwarding to `example.com:80` with text key `secret`:

   ```bash
   python3 src/xor_proxy.py --listen-port 8080 --upstream-host example.com --upstream-port 80 --protocol tcp --key secret
   ```

   To supply the key in hex, prefix with `0x` (e.g., `--key 0xdeadbeef`).

2. Add PF rules to redirect traffic to the proxy. The `examples/pf_anchor.conf` file shows a minimal anchor that redirects TCP traffic destined for `example.com` on port `80` to the local proxy port `8080`:

   ```bash
   sudo pfctl -evf /etc/pf.conf
   sudo pfctl -a xorproxy -f examples/pf_anchor.conf
   ```

   Ensure your `/etc/pf.conf` has an `anchor "xorproxy"` and `load anchor "xorproxy" from "/etc/pf.anchors/xorproxy"` line or adjust the path accordingly.

3. When finished, remove the anchor or flush PF:

   ```bash
   sudo pfctl -a xorproxy -F rules
   ```

### UDP mode

The proxy can also handle UDP flows. Start it with `--protocol udp` and adjust the PF rule to redirect UDP traffic. The UDP handler keeps the last seen client address to return responses, making it suitable for single-client testing scenarios.

## Development

- Run a quick syntax check:

  ```bash
  python3 -m compileall src
  ```

- For debugging, enable verbose logging with `--verbose`.

## Limitations

- This is a user-space proxy; it is not a kernel extension and therefore adds context switches and latency.
- The UDP implementation tracks only the most recent client address, so it is best for simple or single-client use cases.
- PF rule management is manual; ensure you understand your macOS firewall configuration before deploying in production.
