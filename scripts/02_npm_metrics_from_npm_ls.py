#!/usr/bin/env python3
import json
import argparse
from pathlib import Path
from collections import defaultdict, deque

def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--npm-ls", required=True, help="runs/.../npm/npm_ls.json")
    ap.add_argument("--out", required=True, help="Output TSV path")
    args = ap.parse_args()

    root = load_json(Path(args.npm_ls))

    # Build adjacency (forward deps) and reverse adjacency
    forward = defaultdict(set)
    reverse = defaultdict(set)

    # Node key format: "name@version"
    def node_key(name, version):
        return f"{name}@{version}" if version else name

    # Walk npm ls tree
    seen = set()
    stack = [(root.get("name",""), root.get("version",""), root.get("dependencies") or {})]

    root_key = node_key(root.get("name",""), root.get("version",""))

    while stack:
        parent_name, parent_ver, deps = stack.pop()
        parent = node_key(parent_name, parent_ver)

        if not isinstance(deps, dict):
            continue

        for dep_name, dep_obj in deps.items():
            if not isinstance(dep_obj, dict):
                continue
            ver = dep_obj.get("version") or ""
            child = node_key(dep_name, ver)

            forward[parent].add(child)
            reverse[child].add(parent)

            child_deps = dep_obj.get("dependencies") or {}
            # avoid infinite loops
            sig = (dep_name, ver, id(child_deps))
            if sig in seen:
                continue
            seen.add(sig)
            stack.append((dep_name, ver, child_deps))

    # Compute depth from root via BFS
    depth = {root_key: 0}
    q = deque([root_key])
    while q:
        u = q.popleft()
        for v in forward.get(u, []):
            if v not in depth:
                depth[v] = depth[u] + 1
                q.append(v)

    # Compute blast radius: number of unique transitive reverse dependents (excluding itself)
    def transitive_reverse_count(start):
        visited = set()
        dq = deque([start])
        visited.add(start)
        while dq:
            x = dq.popleft()
            for p in reverse.get(x, []):
                if p not in visited:
                    visited.add(p)
                    dq.append(p)
        visited.discard(start)
        return len(visited)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        f.write("npm_node\tname\tversion\tdepth\tblast_radius\tparents\n")
        for n in sorted(depth.keys()):
            if n == root_key:
                continue
            # split name/version
            if "@" in n and not n.startswith("@"):
                name, ver = n.rsplit("@", 1)
            else:
                # scoped pkgs: @scope/name@ver -> split last @
                if n.count("@") >= 2:
                    name, ver = n.rsplit("@", 1)
                else:
                    name, ver = n, ""
            parents = sorted(reverse.get(n, []))
            f.write(
                f"{n}\t{name}\t{ver}\t{depth.get(n,'')}\t{transitive_reverse_count(n)}\t{','.join(parents)}\n"
            )

    print(f"[OK] wrote npm metrics: {out_path}")

if __name__ == "__main__":
    main()
