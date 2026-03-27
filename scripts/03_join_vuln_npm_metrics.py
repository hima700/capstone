#!/usr/bin/env python3
import argparse
from pathlib import Path

def read_tsv(path: Path):
    lines = path.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    rows = [dict(zip(header, ln.split("\t"))) for ln in lines[1:] if ln.strip()]
    return header, rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vuln-components", required=True)
    ap.add_argument("--npm-metrics", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    _, vc_rows = read_tsv(Path(args.vuln_components))
    _, nm_rows = read_tsv(Path(args.npm_metrics))

    # map by (name, version)
    nm = {}
    for r in nm_rows:
        nm[(r["name"], r["version"])] = r

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open("w", encoding="utf-8") as f:
        f.write("name\tversion\tpurl\tvuln_count\tmax_severity\tdepth\tblast_radius\n")
        for r in vc_rows:
            if r["ecosystem"] != "npm":
                continue
            key = (r["name"], r["version"])
            m = nm.get(key, {})
            f.write(
                f"{r['name']}\t{r['version']}\t{r['purl']}\t{r['vuln_count']}\t{r['max_severity']}\t"
                f"{m.get('depth','')}\t{m.get('blast_radius','')}\n"
            )

    print(f"[OK] wrote vulnerable npm with metrics: {out}")

if __name__ == "__main__":
    main()
