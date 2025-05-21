import os
import subprocess
import json
import sys
from pathlib import Path
from datetime import datetime, timedelta

REPO_URL = "https://github.com/CVEProject/cvelistV5.git"
LOCAL_REPO = "cvelistV5"
TECH_FILE = "tech_list.txt"

OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

def clone_or_update_repo():
    if not os.path.exists(LOCAL_REPO):
        subprocess.run(["git", "clone", REPO_URL, LOCAL_REPO], check=True)
    else:
        subprocess.run(["git", "-C", LOCAL_REPO, "pull"], check=True)

def load_tech_keywords():
    if not os.path.exists(TECH_FILE):
        return []
    with open(TECH_FILE) as f:
        return [l.strip().lower() for l in f if l.strip()]

def find_recent_json_files():
    cmd = [
        "git", "-C", LOCAL_REPO,
        "log",
        "--since=24 hours ago",
        "--diff-filter=A",
        "--name-only",
        "--pretty="
    ]
    try:
        out = subprocess.check_output(cmd, text=True)
    except subprocess.CalledProcessError:
        return []
    files = set()
    for line in out.splitlines():
        if line.strip().endswith(".json"):
            path = Path(LOCAL_REPO) / line.strip()
            if path.exists():
                files.add(path)
    return list(files)

def get_highest_cvss_score(metrics):
    scores = []
    for m in metrics:
        for key in ("cvssV4_0","cvssV3_1","cvssV3_0","cvssV2_0"):
            if key in m and "baseScore" in m[key]:
                scores.append(m[key]["baseScore"])
    return max(scores) if scores else 0.0

def scan_file(json_path, techs):
    """
    Ritorna (tech, title, score) se match e score>=7.0, altrimenti None.
    """
    with open(json_path) as f:
        data = json.load(f)
    cna = data.get("containers",{}).get("cna",{})
    score = get_highest_cvss_score(cna.get("metrics",[]))
    if score < 4.0:
        return None

    texts = [cna.get("title","")]
    texts += [d.get("value","") for d in cna.get("descriptions",[])]
    for a in cna.get("affected",[]):
        texts += [a.get("vendor",""), a.get("product","")]
    for r in cna.get("references",[]):
        texts += [r.get("name",""), r.get("url","")]
    txt = " ".join(texts).lower()

    for tech in techs:
        if tech in txt:
            return tech, cna.get("title",""), score

    return None

def main():
    clone_or_update_repo()
    techs = load_tech_keywords()
    if not techs:
        print("UNKNOWN - tech_list.txt mancante o vuoto")
        sys.exit(UNKNOWN)

    files = find_recent_json_files()
    matches = []
    for jf in files:
        res = scan_file(jf, techs)
        if res:
            matches.append((jf, *res))

    if not matches:
        print("OK - nessuna CVE critica trovata")
        sys.exit(OK)

    exit_code = OK
    details = []
    for path, tech, title, score in matches:
        sev = CRITICAL if score >= 9 else WARNING
        exit_code = max(exit_code, sev)
        details.append(f"{tech.upper()}[{score}] {path.name}")

    status_str = "CRITICAL" if exit_code == CRITICAL else "WARNING"
    print(f"{status_str} - {len(matches)} CVE critiche trovate: " + "; ".join(details))
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
