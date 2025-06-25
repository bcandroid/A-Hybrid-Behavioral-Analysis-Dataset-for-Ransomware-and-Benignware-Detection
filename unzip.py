import os
import sys
import pyzipper

ZIP_PASSWORD = b'infected'
path = '/home/remnux/Downloads/ransomware/windows/unzips_exe'

if not os.path.exists(path):
    print(f"The directory {path} does not exist.")
    sys.exit(1)

file_names = os.listdir(path)

for file_name in file_names:
    absolute_file_name = os.path.join(path, file_name)
    print(f"Attempting to extract: {absolute_file_name}")
    
    try:
        with pyzipper.AESZipFile(absolute_file_name) as zf:
            zf.pwd = ZIP_PASSWORD
            zf.extractall(".")
            print(f"Successfully extracted: {file_name}")
    except (pyzipper.BadZipFile, RuntimeError) as e:
        print(f"Failed to extract {file_name}: {e}")
