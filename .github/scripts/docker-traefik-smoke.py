#!/usr/bin/env python3
"""Generate native Traefik JSON and replay it through the production Custos image."""
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def docker(*args, check=True):
    return subprocess.run(["docker", *args], text=True, capture_output=True, check=check)


def main():
    name = "custos-traefik-" + uuid.uuid4().hex[:10]
    image = os.environ.get("CUSTOS_TRAEFIK_IMAGE", "traefik:v3.5")
    with tempfile.TemporaryDirectory(prefix="custos-traefik-") as directory:
        tmp = pathlib.Path(directory)
        # Replay stays entirely local: no native firewall, Hub, or external model.
        tmp.joinpath("config.toml").write_text('''
[daemon]
decisions_file = "/tmp/traefik-decisions.jsonl"
[firewall]
enabled = false
''')
        try:
            docker("run", "-d", "--name", name, "-p", "127.0.0.1::8000",
                   "-v", f"{directory}:/logs", image,
                   "--entrypoints.web.address=:8000", "--accesslog=true",
                   "--accesslog.format=json", "--accesslog.filepath=/logs/access.log")
            port = int(docker("inspect", "--format",
                              '{{(index (index .NetworkSettings.Ports "8000/tcp") 0).HostPort}}',
                              name).stdout.strip())
            deadline = time.monotonic() + 10
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AssertionError("Traefik did not become ready")
                    time.sleep(0.1)
            # No router/backend: these are Traefik's own 404 responses, OriginStatus=0.
            for path in ["/microservice/.env", "/service/.env", "/api/v3/.env", "/api/dev/.env", "/api/staging/.env"]:
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5).close()
                    raise AssertionError("Unrouted probe unexpectedly succeeded")
                except urllib.error.HTTPError as error:
                    assert error.code == 404
                    error.close()
            records = []
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    records = [json.loads(line) for line in tmp.joinpath("access.log").read_text().splitlines()]
                except (FileNotFoundError, json.JSONDecodeError):
                    records = []  # Wait for a complete record if Traefik is writing.
                if len(records) == 5:
                    break
                time.sleep(0.1)
            assert len(records) == 5
            assert all(r["DownstreamStatus"] == 404 and r.get("OriginStatus", 0) == 0 for r in records)
            replay = docker("run", "--rm", "--network", "none", "-v", f"{directory}:/test:ro",
                            "custos:ci", "--config", "/test/config.toml", "replay",
                            "--log", "/test/access.log", "--format", "json", "--mock-jev")
            assert "5 parsed events" in replay.stdout, replay.stdout
            assert "vulnerability_scanner" in replay.stdout, replay.stdout
            assert "Jev L2 Actor Verdicts (1)" in replay.stdout, replay.stdout
            print(f"Native {image} JSON: 5/5 records parsed, proxy-generated 404s retained, 1 scanner conviction")
        except Exception:
            logs = docker("logs", "--tail", "20", name, check=False)
            print(logs.stdout, logs.stderr)
            raise
        finally:
            docker("rm", "-fv", name, check=False)


if __name__ == "__main__":
    main()
