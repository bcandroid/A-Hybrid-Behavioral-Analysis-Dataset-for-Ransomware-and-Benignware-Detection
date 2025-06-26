import requests
import sys
import pandas as pd
import json

def check_sha256(s):
    if s == "":
        return
    if len(s) != 64:
        raise ValueError(f"Please use sha256 value instead of '{s}'")
    return str(s)

def download_sample(sha256_hash, info=False):
    if info:
        data = {
            'query': 'get_info',
            'hash': sha256_hash,
        }
        response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, timeout=15, stream=True)
        print(response.content.decode("utf-8", "ignore"))
    else:
        data = {
            'query': 'get_file',
            'sha256_hash': sha256_hash,
        }

        with requests.post('https://mb-api.abuse.ch/api/v1/', data=data, timeout=15, stream=True) as response:
            if 'file_not_found' in response.text:
                print(f"Error: file for hash {sha256_hash} not found")
            else:
                with open(f"{sha256_hash}.zip", 'wb') as file:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:  # filter out keep-alive new chunks
                            file.write(chunk)
                print(f"Sample \"{sha256_hash}\" downloaded.")


def csv():
    file_path = '/home/remnux/Downloads/calisma/ransom/sonuc_dosyasi.csv'
    try:
        df = pd.read_csv(file_path)
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        sys.exit()
    df = df.iloc[0:] 
    first_column = df.iloc[:, 0]
    filtered_column = first_column[~first_column.isin(['filename', 'content', 'yes'])]
    return filtered_column

if __name__ == "__main__":
    filtered_column = csv()

    for sha256_hash in filtered_column:
        sha256_hash = sha256_hash.strip()
        try:
            check_sha256(sha256_hash)
        except ValueError as e:
            print(e)
            continue

        download_sample(sha256_hash, info=False)  # Pass info=False explicitly
