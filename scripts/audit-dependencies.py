#!/usr/bin/env python3
"""Query OSV for locked Rust and Agent Go dependencies; never read workspace data.

This records database matches, not exploitability or a clean bill of health.
Review reachability and target platforms separately. npm audit remains a separate
check because its lockfile and advisory service have different semantics.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent.parent


def request_json(url, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = Request(url, data=data, headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=60) as response:
        return json.load(response)


def main():
    output = Path(sys.argv[1]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    # The isolated parser is a separately built production component. Scan its
    # lockfile too, deduplicating shared crate versions rather than omitting it.
    rust_packages = {}
    for lockfile in ["src-tauri/Cargo.lock", "reverse-worker/Cargo.lock"]:
        lock = tomllib.loads((ROOT / lockfile).read_text())
        for p in lock["package"]:
            if p.get("source", "").startswith("registry+"):
                rust_packages[(p["name"], p["version"])] = {
                    "ecosystem": "crates.io", "name": p["name"], "version": p["version"]}
    packages = list(rust_packages.values())
    # Scan modules selected by the production Agent packages. Unused/test-only
    # modules in go.sum are not a claim about the shipped binary. GOPROXY=off
    # and readonly prevent this check from silently changing dependencies.
    raw = subprocess.check_output(
        [os.environ.get("GAGA_GO", "go"), "list", "-mod=readonly", "-deps", "-f",
         "{{with .Module}}{{.Path}} {{.Version}}{{end}}", "./..."],
        cwd=ROOT / "agent", env={**os.environ, "GOPROXY": "off"}, text=True,
    )
    for module in sorted(set(raw.splitlines())):
        parts = module.split()
        if len(parts) == 2:
            packages.append({"ecosystem": "Go", "name": parts[0], "version": parts[1]})
    toolchain = subprocess.check_output(
        [os.environ.get("GAGA_GO", "go"), "version"], cwd=ROOT / "agent", text=True,
    )
    version = re.search(r"go(\d+\.\d+(?:\.\d+)?)", toolchain).group(1)
    packages.append({"ecosystem": "Go", "name": "stdlib", "version": version})
    matches = []
    for start in range(0, len(packages), 100):
        batch = packages[start:start + 100]
        result = request_json("https://api.osv.dev/v1/querybatch", {"queries": [
            {"package": {"ecosystem": p["ecosystem"], "name": p["name"]}, "version": p["version"]}
            for p in batch
        ]})
        if len(result["results"]) != len(batch):
            raise RuntimeError("OSV result count mismatch; refusing incomplete success")
        matches.extend({**p, "vulns": r["vulns"]} for p, r in zip(batch, result["results"]) if r.get("vulns"))
    report = {"source": "OSV public API querybatch", "packages": len(packages), "rustLockfiles": ["src-tauri/Cargo.lock", "reverse-worker/Cargo.lock"],
              "toolchain": toolchain.strip(), "affected": matches}
    (output / "dependency-osv.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))
    details = {vid: request_json("https://api.osv.dev/v1/vulns/" + vid)
               for vid in sorted({v["id"] for p in matches for v in p["vulns"]})}
    (output / "dependency-advisories.json").write_text(json.dumps(details, ensure_ascii=False, indent=2))
    print(json.dumps({"packages": len(packages), "rustLockfiles": ["src-tauri/Cargo.lock", "reverse-worker/Cargo.lock"], "matchedPackages": len(matches), "output": str(output)}))


if __name__ == "__main__":
    main()
