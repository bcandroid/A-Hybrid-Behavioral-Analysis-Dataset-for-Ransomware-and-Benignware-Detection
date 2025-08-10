#!/usr/bin/env python3
import os, re, csv, json, requests

CSV_PATH      = "/path/to/your/list.csv"  
DOWNLOAD_DIR  = "downloads"
INFO_LOG      = "malware_list.jsonl"
TAG_FILTER    = "exe"                     
LIMIT         = None                      

MB_API = "https://mb-api.abuse.ch/api/v1/"
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

def extract_sha256(text):
    if not text: return None
    m = SHA256_RE.search(str(text))
    return m.group(0).lower() if m else None

def download_sample(sha256_hash, save_path):
    try:
        with requests.post(MB_API, data={"query":"get_file","sha256_hash":sha256_hash},
                           timeout=30, stream=True) as r:
            if r.status_code == 200 and b'file_not_found' not in r.content[:200]:
                with open(save_path, "wb") as f:
                    for chunk in r.iter_content(8192):
                        if chunk: f.write(chunk)
                print(f"[+] Downloaded: {save_path}")
                return True
            else:
                print(f"[!] Not found or error: {sha256_hash}")
                return False
    except Exception as e:
        print(f"[!] Error downloading {sha256_hash}: {e}")
        return False

def fetch_tags(sha256_hash):
    try:
        r = requests.post(MB_API, data={"query":"get_info","hash":sha256_hash}, timeout=20)
        if r.status_code != 200: return []
        data = r.json().get("data", [])
        if not data: return []
        return data[0].get("tags", []) or []
    except Exception:
        return []

def main():
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    written = 0

    with open(INFO_LOG, "w", encoding="utf-8") as logf, open(CSV_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=1):
            if LIMIT is not None and i > LIMIT: break

            sha = extract_sha256(row.get("file_name"))
            if not sha:
                print(f"[-] Satır {i}: SHA256 bulunamadı, atlandı.")
                continue

            tags = fetch_tags(sha)

            entry = {"sha256_hash": sha, "tags": tags}
            logf.write(json.dumps(entry) + "\n")

            save_path = os.path.join(DOWNLOAD_DIR, f"{sha}.zip")
            if os.path.exists(save_path):
                print(f"[=] Zaten var: {save_path}")
                continue

            print(f"[*] İndiriliyor: {sha}  (tags: {tags})")
            download_sample(sha, save_path)

if __name__ == "__main__":
    main()
