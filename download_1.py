import requests
import json

tagg = "exe"  

response = requests.post('https://mb-api.abuse.ch/api/v1/', {
    'query': 'get_taginfo',
    'tag': 'ransomware',
    'limit': '1000'
})

if response.status_code == 200:
    response_dict = response.json()
    malware_list = response_dict['data']
    
    with open('malware_list.txt', 'w') as file:
        for dic in malware_list:
            sha256_hash = dic.get('sha256_hash')
            extention = dic.get('file_type')
            tags = dic.get('tags', [])

            if tagg in tags or (extention is not None and tagg == extention):
                tag_str = ','.join(tags) 
                entry = {
                    'sha256_hash': sha256_hash,
                    'tags': tag_str
                }
                json.dump(entry, file)
                file.write("\n")
                print(f"Downloading file: {sha256_hash}")
                data = {'query': 'get_file', 'sha256_hash': sha256_hash}
                response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, timeout=50, allow_redirects=True)

                if response.status_code == 200:
                    with open(sha256_hash, 'wb') as f:
                        f.write(response.content)
                else:
                    print(f"Error downloading file: {sha256_hash}")
else:
    print("Error: Unable to fetch data from API.")
