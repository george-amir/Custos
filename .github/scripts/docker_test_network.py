"""Create disposable networks with explicit, non-overlapping IPv4 subnets."""
import ipaddress
import json
import secrets


def create_test_network(docker, name, ipv6=None):
    ids = docker("network", "ls", "-q").stdout.split()
    networks = json.loads(docker("network", "inspect", *ids).stdout) if ids else []
    occupied = [ipaddress.ip_network(item["Subnet"], strict=False)
                for network in networks for item in ((network.get("IPAM") or {}).get("Config") or [])
                if item.get("Subnet") and ":" not in item["Subnet"]]
    for _ in range(128):
        subnet = ipaddress.ip_network(f"10.{secrets.randbelow(256)}.{secrets.randbelow(256)}.0/24")
        if any(subnet.overlaps(other) for other in occupied):
            continue
        args = ["network", "create", "--subnet", str(subnet)]
        if ipv6:
            args += ["--ipv6", "--subnet", ipv6]
        result = docker(*args, name, check=False)
        if result.returncode == 0:
            return subnet
        if "overlap" not in result.stderr.lower():
            raise RuntimeError(result.stderr)
    raise RuntimeError("No unused private subnet for the disposable Docker test")
