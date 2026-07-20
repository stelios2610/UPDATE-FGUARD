#!/bin/bash
# Post-update migration script — runs automatically after each update is applied.
# Every block must be idempotent (safe to run multiple times).

# ── Ensure wg0 INPUT rule exists ─────────────────────────────────────────────
# Added in v1.0.4: WireGuard traffic arriving on wg0 must be accepted in INPUT
if ! iptables -C INPUT -i wg0 -j ACCEPT 2>/dev/null; then
    iptables -I INPUT -i wg0 -j ACCEPT 2>/dev/null || true
    netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
fi
