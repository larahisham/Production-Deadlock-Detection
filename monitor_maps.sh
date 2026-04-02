#!/bin/bash
while true; do
    clear
    echo "=== HELD LOCKS ==="
    sudo bpftool map dump name held_locks_map 2>/dev/null | head -10 || echo "Empty"
    echo ""
    echo "=== LOCK INFO ==="
    sudo bpftool map dump name lock_info_map 2>/dev/null | head -10 || echo "Empty"
    echo ""
    echo "[$(date '+%H:%M:%S')]"
    sleep 1
done
