#hexdump -C ./83b294975e094024bdeb90f5cdeb9832304cf6879a27eee5cfe08650e5731674.exe | head

import os
import pefile
import shutil

directory = os.path.expanduser('/home/remnux/Downloads/ransomware/windows/zipped_exe')

target_dirs = {
    0x014C: "x86 (32-bit)",
    0x8664: "x86-64 (x64)",
    0x01C0: "ARM",
    0xAA64: "ARM64",
    0x0366: "MIPS",
    0x01F0: "PowerPC",
    0xF3: "RISC-V (deneysel)"
}

for dir_name in target_dirs.values():
    os.makedirs(dir_name, exist_ok=True)


for filename in os.listdir(directory):
    if filename.endswith('.exe'):
        file_path = os.path.join(directory, filename)
        
        try:
       
            pe = pefile.PE(file_path)
            machine_type = pe.FILE_HEADER.Machine
            if machine_type in target_dirs:
                target_dir = target_dirs[machine_type]
                shutil.move(file_path, os.path.join(target_dir, filename))
                print(f"{filename} dosyasÄ± {target_dir} dizinine taÅÄ±ndÄ±.")
            else:
                print(f"{machine_type} dosyasÄ± bilinmeyen bir mimari iÃ§eriyor.")
        
        except Exception as e:
            print(f"{machine_type} dosyasÄ± iÅlenirken hata oluÅtu: {e}")
