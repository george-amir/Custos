#!/usr/bin/env python3
"""Exercise the README's Nginx integration in an isolated Docker network."""
import datetime
import json
import pathlib
import re
import subprocess
import tempfile
import time
import uuid


def docker(*args, check=True):
    return subprocess.run(["docker", *args], text=True, capture_output=True, check=check)


def main():
    name = "custos-proxy-" + uuid.uuid4().hex[:10]
    engine, proxy = name + "-engine", name + "-nginx"
    root = pathlib.Path(__file__).resolve().parents[2]
    snippet = root.joinpath("README.md").read_text().split(
        "### Nginx (`ngx_http_auth_request_module`)", 1
    )[1].split("```nginx\n", 1)[1].split("```", 1)[0]
    # The backend uses a second port so auth_request runs before proxying.
    snippet += '\nserver { listen 3000; location / { return 200 "ok\\n"; } }\n'
    with tempfile.TemporaryDirectory(prefix="custos-proxy-") as directory:
        tmp = pathlib.Path(directory)
        tmp.joinpath("nginx.conf").write_text(snippet)
        tmp.joinpath("access.log").touch()
        tmp.joinpath("config.toml").write_text('''
[daemon]
bouncer_listen = "0.0.0.0:8085"
decisions_file = "/var/lib/custos/decisions.jsonl"
[[logs]]
path = "/test/access.log"
format = "json"
[window]
window_secs = 1
flush_interval_ms = 100
l1_flood_threshold = 3
throttle_secs = 5
[firewall]
enabled = false
''')
        docker("network", "create", name)
        try:
            docker("run", "-d", "--name", engine, "--network", name,
                   "--network-alias", "custos", "-v", f"{directory}:/test:ro",
                   "custos:ci", "--config", "/test/config.toml", "run", "--mock-jev")
            for _ in range(50):
                if docker("exec", engine, "custos", "stats", check=False).returncode == 0:
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("Custos did not become ready")
            address = docker("inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", engine).stdout.strip()
            tmp.joinpath("nginx.conf").write_text(snippet.replace("127.0.0.1:8085", address + ":8085"))
            docker("run", "-d", "--name", proxy, "--network", name, "-v",
                   f"{tmp / 'nginx.conf'}:/etc/nginx/conf.d/default.conf:ro", "nginx:alpine")
            docker("exec", proxy, "nginx", "-t")

            def request(path="/", post=False):
                result = docker("exec", proxy, "curl", "-sS", "-D", "-", "-o", "/dev/null",
                                *(["-X", "POST"] if post else []),
                                "http://127.0.0.1" + path, check=False)
                statuses = re.findall(r"HTTP/\S+ (\d{3})", result.stdout)
                return (int(statuses[-1]) if statuses else 0), result.stdout + result.stderr

            def wait_status(expected, path="/", post=False):
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    status, headers = request(path, post)
                    if status == expected:
                        return headers
                    time.sleep(0.1)
                raise AssertionError(f"Expected HTTP {expected}, got {status}: {headers}")

            def append(ip, method, path, status):
                record = dict(timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                              client_ip=ip, method=method, path=path, query="", status=status,
                              bytes_sent=0, referer="-", user_agent="MobileApp/1.0")
                with tmp.joinpath("access.log").open("a") as log:
                    log.write(json.dumps(record) + "\n")

            wait_status(200)
            # Verify the parent POST method reaches Custos through Nginx's GET subrequest.
            append("198.51.100.44", "POST", "/.env", 404)
            wait_status(403, "/.env", post=True)
            wait_status(200, "/.env")
            wait_status(200)
            for _ in range(3):
                append("127.0.0.1", "GET", "/api/feed", 200)
            headers = wait_status(429)
            assert re.search(r"Retry-After:\s*[1-5]\b", headers, re.I), headers
            # A real ban takes precedence over a temporary throttle and stays 403.
            append("127.0.0.1", "GET", "/.env", 404)
            headers = wait_status(403)
            assert "retry-after:" not in headers.lower(), headers
            print("Nginx README integration: allow=200, throttle=429 with Retry-After, "
                  "ban=403, original POST signature=403, unmatched GET=200")
        except Exception:
            for container in (proxy, engine):
                logs = docker("logs", "--tail", "30", container, check=False)
                print(logs.stdout, logs.stderr)
            raise
        finally:
            for container in (proxy, engine):
                docker("rm", "-fv", container, check=False)
            docker("network", "rm", name, check=False)


if __name__ == "__main__":
    main()
