import requests
import pandas as pd
from time import sleep

# requests setup
requests.urllib3.disable_warnings()
client = requests.session()
client.verify = False

apikey = ".........."


def download_file(apikey, filehash):
    url = f"https://www.virustotal.com/api/v3/files/{filehash}/download"
    headers = {"x-apikey": apikey}

    # API iste?i
    r = client.get(url, headers=headers, stream=True)

    if r.status_code == 429:
        print('Encountered rate-limiting. Sleeping for 45 seconds.')
        sleep(45)
        download_file(apikey, filehash)

    elif r.status_code == 404:
        print(f"File not found for hash: {filehash}")
        return

    elif r.status_code != 200:
        print(f"HTTP Error: {r.status_code}")
        print(r.text)
        return

    elif r.status_code == 200:
        filename = f"{filehash}.exe"
        with open(filename, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        print(f"File {filename} downloaded successfully.")


def csv():
    file_path = '/home/remnux/Downloads/calisma/ransom/processed_output.csv'
    try:
        df = pd.read_csv(file_path)
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        exit(1)
    first_column = df.iloc[:, 0]
    return first_column


if __name__ == "__main__":
    filtered_column = csv()
    for sha256_hash in filtered_column:
        sha256_hash = sha256_hash.strip()
        download_file(apikey, sha256_hash)
