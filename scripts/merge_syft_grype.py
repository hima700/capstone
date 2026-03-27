#!/usr/bin/env python3
import json
import sys
from pathlib import Path

def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))

def main():
    if len(sys.argv) != 4:
        print("Usage: merge_cdx_vulns.py <syft_cdx.json> <grype_cdx_vulns.json> <out_merged.json>")
        sys.exit(1)

    syft_path = Path(sys.argv[1])
    grype_path = Path(sys.argv[2])
    out_path = Path(sys.argv[3])

    syft = load_json(syft_path)
    grype = load_json(grype_path)

    # Grype CycloneDX output should already be: {"bomFormat":"CycloneDX", ..., "vulnerabilities":[...]}
    vulns = grype.get("vulnerabilities", [])
    if not isinstance(vulns, list):
        print("[ERROR] grype input does not contain a CycloneDX vulnerabilities[] array.")
        sys.exit(2)

    # Merge vulnerabilities into Syft SBOM
    syft["vulnerabilities"] = vulns

    # (Optional) carry over tool info from grype into metadata.tools if you want provenance
    # Keep Syft as primary; append Grype tool component if present and not already listed.
    try:
        syft_tools = syft.setdefault("metadata", {}).setdefault("tools", {}).setdefault("components", [])
        grype_tools = grype.get("metadata", {}).get("tools", {}).get("components", [])
        if isinstance(grype_tools, list):
            for t in grype_tools:
                # add only if not already present by (name, version)
                name = t.get("name")
                ver = t.get("version")
                exists = any(x.get("name") == name and x.get("version") == ver for x in syft_tools)
                if name and not exists:
                    syft_tools.append(t)
    except Exception:
        pass

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(syft, indent=2), encoding="utf-8")
    print(f"[OK] Wrote merged CycloneDX SBOM: {out_path}")

if __name__ == "__main__":
    main()
