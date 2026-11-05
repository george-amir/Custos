#!/usr/bin/env python3
"""Verify IPv4/IPv6 forwarding, restart recovery, and real Traefik ForwardAuth.

All firewall/NAT rules live inside a disposable router container. Nothing uses
host networking or modifies the Docker host's firewall. No extra client image.
"""
import datetime
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from docker_test_network import create_test_network


def docker(*args, check=True, timeout=30, input=None):
    return subprocess.run(["docker", *args], text=True, input=input,
                          capture_output=True, check=check, timeout=timeout)


def main():
    suffix = uuid.uuid4().hex[:8]
    name = "custos-forward-" + suffix
    router, backend, client, proxy = [name + "-" + part for part in ("router", "backend", "client", "traefik")]
    network_a, network_b = name + "-a", name + "-b"
    image = os.environ.get("CUSTOS_TEST_IMAGE", "custos:ci")
    token = "isolated-test-only"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with tempfile.TemporaryDirectory(prefix="custos-forward-") as directory:
        tmp = Path(directory)
        for folder in ("router", "backend"):
            tmp.joinpath(folder).mkdir()
            tmp.joinpath(folder, "access.log").touch()
        try:
            for network, part in ((network_a, "a"), (network_b, "b")):
                prefix = f"fd42:{suffix[:4]}:{suffix[4:]}:{part}::/64"
                create_test_network(docker, network, prefix)
            configuration = json.loads(docker("network", "inspect", network_a).stdout)[0]["IPAM"]["Config"]
            subnet = next(ipaddress.ip_network(item["Subnet"]) for item in configuration
                          if ipaddress.ip_network(item["Subnet"]).version == 4)
            router_a, client_a, proxy_a = [str(subnet.network_address + i) for i in (2, 3, 4)]
            for folder, live in (("router", True), ("backend", False)):
                tmp.joinpath(folder, "config.toml").write_text(f'''
[daemon]
bouncer_listen = "[::]:8085"
decisions_file = "/state/ledger"
api_token = "{token}"
trusted_proxies = [{json.dumps(proxy_a)}]
[[logs]]
path = "/state/access.log"
format = "json"
[window]
window_secs = 1
flush_interval_ms = 100
[firewall]
enabled = {str(live).lower()}
dry_run = false
backend = "nftables"
protect_docker = {str(live).lower()}
[crawlers]
auto_refresh = false
''')
            docker("run", "-d", "--name", backend, "--network", network_b,
                   "-v", f"{tmp / 'backend'}:/state", image,
                   "--config", "/state/config.toml", "run", "--mock-jev")
            docker("run", "-d", "--name", router, "--network", network_a, "--ip", router_a,
                   "--cap-add=NET_ADMIN", "--sysctl", "net.ipv4.ip_forward=1",
                   "--sysctl", "net.ipv6.conf.all.forwarding=1", "-p", "127.0.0.1::8085",
                   "-v", f"{tmp / 'router'}:/state", image,
                   "--config", "/state/config.toml", "run", "--mock-jev")
            docker("network", "connect", network_b, router)
            docker("run", "-d", "--name", client, "--network", network_a, "--ip", client_a,
                   "-e", "HTTP_PROXY=", "-e", "HTTPS_PROXY=", "-e", "ALL_PROXY=", "-e", "NO_PROXY=*",
                   "--entrypoint", "sleep", image, "300")

            def addresses(container, network):
                data = json.loads(docker("inspect", container).stdout)[0]["NetworkSettings"]["Networks"][network]
                return str(ipaddress.ip_address(data["IPAddress"])), str(ipaddress.ip_address(data["GlobalIPv6Address"]))

            root = "http://" + docker("port", router, "8085/tcp").stdout.strip().splitlines()[0]

            def request(path, method="GET", payload=None):
                req = urllib.request.Request(root + path, method=method,
                    data=None if payload is None else json.dumps(payload).encode(),
                    headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
                with opener.open(req, timeout=5) as response:
                    return json.loads(response.read())

            def ready():
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    try:
                        request("/v1/stats")
                        return
                    except (OSError, urllib.error.URLError):
                        time.sleep(.1)
                raise AssertionError("daemon did not become ready")

            def routing():
                destination4, destination6 = addresses(backend, network_b)
                for family, address in (("ip", destination4), ("ip6", destination6)):
                    target = address + ":8085" if family == "ip" else f"[{address}]:8085"
                    docker("exec", "-i", router, "nft", "-f", "-", input=f'''
add table {family} custos_test_route
add chain {family} custos_test_route ingress {{ type nat hook prerouting priority dstnat; policy accept; }}
add rule {family} custos_test_route ingress tcp dport 18085 dnat to {target}
add chain {family} custos_test_route egress {{ type nat hook postrouting priority srcnat; policy accept; }}
add rule {family} custos_test_route egress {family} daddr {address} tcp dport 8085 masquerade
''')

            def forwarded(address, allowed):
                host = address if ":" not in address else f"[{address}]"
                try:
                    result = docker("exec", client, "custos", "stats", "--api-url", f"http://{host}:18085", timeout=3, check=False)
                    success = result.returncode == 0 and '"events_processed"' in result.stdout
                except subprocess.TimeoutExpired:
                    success = False
                assert success == allowed, (address, allowed)

            ready()
            routing()
            router4, router6 = addresses(router, network_a)
            client4, client6 = addresses(client, network_a)
            forwarded(router4, True)
            forwarded(router6, True)

            # A real proxy must send X-Forwarded-Method/Uri, not our legacy aliases.
            backend4, _ = addresses(backend, network_b)
            tmp.joinpath("traefik.yml").write_text(f'''
http:
  routers:
    app:
      rule: "PathPrefix(`/`)"
      entryPoints: [web]
      middlewares: [custos]
      service: app
  middlewares:
    custos:
      forwardAuth:
        address: "http://{router4}:8085/v1/bouncer/check"
        trustForwardHeader: false
        authRequestHeaders: [User-Agent]
  services:
    app:
      loadBalancer:
        servers:
          - url: "http://{backend4}:8085"
''')
            docker("run", "-d", "--name", proxy, "--network", network_a, "--ip", proxy_a,
                   "-v", f"{tmp / 'traefik.yml'}:/etc/traefik/test.yml:ro",
                   os.environ.get("CUSTOS_TRAEFIK_IMAGE", "traefik:v3.5"),
                   "--entrypoints.web.address=:80", "--providers.file.filename=/etc/traefik/test.yml")
            docker("network", "connect", network_b, proxy)

            def proxy_status(path):
                # Bash's TCP client avoids another image/package dependency.
                script = 'exec 3<>/dev/tcp/' + proxy_a + '/80; printf "GET %s HTTP/1.0\\r\\nHost: test.local\\r\\n\\r\\n" "$1" >&3; head -n1 <&3'
                result = docker("exec", client, "bash", "-c", script, "test", path, timeout=5, check=False)
                parts = result.stdout.split()
                return int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0

            deadline = time.monotonic() + 15
            while proxy_status("/v1/stats") != 200 and time.monotonic() < deadline:
                time.sleep(.1)
            initial = proxy_status("/v1/stats")
            assert initial == 200, ("initial proxy response", initial)
            with tmp.joinpath("router", "access.log").open("a") as log:
                log.write(json.dumps({"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "client_ip": "198.51.100.44", "method": "GET", "path": "/.env", "query": "", "status": 404,
                    "bytes_sent": 0, "user_agent": "", "referer": ""}) + "\n")
            deadline = time.monotonic() + 10
            while request("/v1/stats")["auto_cached_signatures"] == 0 and time.monotonic() < deadline:
                time.sleep(.1)
            assert proxy_status("/.env") == 403, "native ForwardAuth metadata did not block the cached path"
            assert proxy_status("/v1/stats") == 200

            for address in (client4, client6):
                request("/v1/decisions", "POST", {"ip": address, "ttl_secs": 300, "reason": "isolated forwarding test"})
            forwarded(router4, False)
            forwarded(router6, False)
            assert proxy_status("/v1/stats") == 403
            counters = json.loads(docker("exec", router, "nft", "-j", "list", "chain", "inet", "custos_block", "docker_forward").stdout)
            counts = [expr["counter"]["packets"] for item in counters["nftables"] for expr in item.get("rule", {}).get("expr", []) if "counter" in expr]
            assert len(counts) == 2 and all(count > 0 for count in counts), counts
            print("ForwardAuth cached-path=403, normal=200; native IPv4/IPv6 forwarding drops:", counts, flush=True)

            docker("restart", router)
            # Docker may choose a new host port when restarting a random binding.
            root = "http://" + docker("port", router, "8085/tcp").stdout.strip().splitlines()[0]
            ready()
            routing()
            assert client4 in docker("exec", router, "nft", "list", "set", "inet", "custos_block", "block_v4").stdout
            assert client6 in docker("exec", router, "nft", "list", "set", "inet", "custos_block", "block_v6").stdout
            forwarded(router4, False)
            forwarded(router6, False)
            # Counter collection happens off the request path once per minute.
            deadline = time.monotonic() + 70
            while time.monotonic() < deadline:
                stats = request("/v1/stats")
                if (stats.get("kernel_dropped_packets") or 0) > 0:
                    break
                time.sleep(1)
            assert stats["kernel_dropped_packets"] > 0, stats
            assert request("/v1/firewall")["command_errors"] == 0
            for address in (client4, client6):
                request("/v1/decisions/" + address, "DELETE")
            forwarded(router4, True)
            forwarded(router6, True)
            print("Restart preserved bans; reported packet drops:", stats["kernel_dropped_packets"], "; unban restored both families", flush=True)
        except Exception:
            for container in (router, backend, proxy):
                result = docker("logs", "--tail", "20", container, check=False)
                print(container, result.stdout, result.stderr)
            raise
        finally:
            for container in (proxy, client, backend, router):
                docker("rm", "-f", container, check=False)
            for network in (network_a, network_b):
                docker("network", "rm", network, check=False)


if __name__ == "__main__":
    main()
