import requests
import json
import os

TAG_FILTER = "exe"
DOWNLOAD_DIR = "downloads"
INFO_LOG = "malware_list.jsonl"

def fetch_ransomware_samples(limit=1000):
    print("[*] Fetching sample metadata from abuse.ch...")
    response = requests.post('https://mb-api.abuse.ch/api/v1/', data={
        'query': 'get_taginfo',
        'tag': 'ransomware',
        'limit': str(limit)
    })

    if response.status_code != 200:
        print(f"[!] Error fetching metadata: {response.status_code}")
        return []

    try:
        data = response.json()
        return data.get('data', [])
    except Exception as e:
        print(f"[!] Failed to parse JSON: {e}")
        return []

def download_sample(sha256_hash, save_path):
    try:
        response = requests.post('https://mb-api.abuse.ch/api/v1/', data={
            'query': 'get_file',
            'sha256_hash': sha256_hash
        }, timeout=30, stream=True)

        if response.status_code == 200 and b'file_not_found' not in response.content:
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            print(f"[+] Downloaded: {save_path}")
        else:
            print(f"[!] File not found or error: {sha256_hash}")

    except Exception as e:
        print(f"[!] Error downloading {sha256_hash}: {e}")

def main():
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)

    samples = fetch_ransomware_samples()

    with open(INFO_LOG, 'w') as log_file:
        for sample in samples:
            sha256_hash = sample.get('sha256_hash')
            file_type = sample.get('file_type', '')
            tags = sample.get('tags', [])

            if not sha256_hash:
                continue

            if TAG_FILTER in tags or TAG_FILTER == file_type:
                # Log JSONL entry
                entry = {
                    'sha256_hash': sha256_hash,
                    'tags': tags
                }
                log_file.write(json.dumps(entry) + "\n")

                # Download sample
                save_path = os.path.join(DOWNLOAD_DIR, f"{sha256_hash}.zip")
                print(f"[*] Downloading file for hash: {sha256_hash}")
                download_sample(sha256_hash, save_path)

if __name__ == "__main__":
    main()
