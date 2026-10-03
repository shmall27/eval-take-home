#!/usr/bin/env python3
"""Check a chat provider using one harmless, bounded text request.

Usage: python3 scripts/provider_smoke.py --env-file .env.abliteration
Requires MODEL, MODEL_BASE_URL, and MODEL_API_KEY. Process environment wins.
"""
import argparse
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward credentials to a redirected destination.
        return None


def load_config(path):
    config = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, separator, value = line.removeprefix("export ").partition("=")
            if separator:
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                config[name.strip()] = value
    for name in ("MODEL", "MODEL_BASE_URL", "MODEL_API_KEY"):
        if name in os.environ:
            config[name] = os.environ[name]
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        config = load_config(args.env_file)
    except OSError:
        print("Cannot read the configuration file.")
        return 2
    required = ("MODEL", "MODEL_BASE_URL", "MODEL_API_KEY")
    missing = [name for name in required if not config.get(name)]
    if missing:
        print("Missing configuration: " + ", ".join(missing))
        return 2
    base = config["MODEL_BASE_URL"].rstrip("/")
    parsed = urllib.parse.urlsplit(base)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        print("MODEL_BASE_URL must be an HTTPS URL without credentials or query parameters.")
        return 2
    body = json.dumps({
        "model": config["MODEL"],
        "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
        "max_tokens": 512,
        "temperature": 0,
    }).encode()
    request = urllib.request.Request(
        base + "/chat/completions", data=body,
        headers={"Authorization": "Bearer " + config["MODEL_API_KEY"],
                 "Content-Type": "application/json"},
    )
    started = time.monotonic()
    try:
        with urllib.request.build_opener(NoRedirects()).open(request, timeout=45) as response:
            result = json.load(response)
        choice = result["choices"][0]
        content = choice["message"].get("content")
    except urllib.error.HTTPError as exc:
        print(f"Connectivity failed: HTTP {exc.code}. Response body omitted to protect credentials.")
        return 1
    except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError, TypeError):
        print("Connectivity failed: network error or unexpected response format.")
        return 1
    if not isinstance(content, str) or content.strip() != "OK":
        print("Provider responded, but did not return the expected OK response.")
        return 1
    print(f"Connectivity verified: OK ({time.monotonic() - started:.1f}s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
