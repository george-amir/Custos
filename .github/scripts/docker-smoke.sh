#!/usr/bin/env bash
set -euo pipefail
# The firewall operates only in this disposable container's network namespace.
log_dir=$(mktemp -d)
name="custos-smoke-$$"
cleanup() {
  docker logs "$name" 2>/dev/null || true
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$log_dir"
}
trap cleanup EXIT
: > "$log_dir/access.log"
docker run -d --name "$name" --cap-add=NET_ADMIN \
  -v "$log_dir:/var/log/nginx:ro" custos:ci \
  --config /etc/custos/config.toml run --mock-jev >/dev/null
ready=false
for _ in $(seq 1 30); do
  if docker exec "$name" custos stats >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
$ready || { echo "Container did not become ready" >&2; exit 1; }
printf '198.51.100.44 - - [%s] "GET /.env HTTP/1.1" 404 12 "-" "Nuclei"\n' "$(date -u '+%d/%b/%Y:%H:%M:%S +0000')" >> "$log_dir/access.log"
blocked=false
for _ in $(seq 1 30); do
  if docker exec "$name" custos check 198.51.100.44 | grep -q 'action=block'; then
    blocked=true
    break
  fi
  sleep 1
done
$blocked || { echo "Mounted access log did not produce a ban" >&2; exit 1; }
docker exec "$name" nft list set inet custos_block block_v4 | grep -q '198.51.100.44'
