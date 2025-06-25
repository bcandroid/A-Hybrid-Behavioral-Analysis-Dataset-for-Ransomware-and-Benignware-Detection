import os
import re
import r2pipe
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
import sys

def process_file(file_name, path, output_dir):
    absolute_file_name = os.path.join(path, file_name)
    write_file_name = os.path.join(output_dir, file_name + '_opcodes.txt')
    
    if os.path.exists(write_file_name):
        print(f"{write_file_name} already exists, skipping.")
        return None

    try:
        print(f"Analyzing: {file_name}")
        malware = r2pipe.open(absolute_file_name)
        malware.cmd("e asm.arch = x86")
        malware.cmd("e asm.bits = 32")
        malware.cmd("e cfg.bigendian=false")
        malware.cmd("e bin.relocs.apply=true")
        malware.cmd("e bin.cache=true")
        malware.cmd("e anal.nopskip=false")
        malware.cmd("e anal.hasnext = true")
        malware.cmd("e anal.bb.maxsize=2097152")  # Set maximum block size
        malware.cmd("aaaa")  # Full analysis
        pdf_output = malware.cmd("pif @@f ~[0]").splitlines()
        
        # Clean and format opcodes
        opcodes = ' '.join(pdf_output).replace('\n', ' ').replace('\r', '')
        
        # Write opcodes to the output file
        with open(write_file_name, "a") as f:
            f.write(opcodes)
        
        print(f"Opcodes saved to: {write_file_name}")
    
    except Exception as e:
        print(f"Error: {e}")


def initial_analysis():
    path = '/home/remnux/Downloads/ransomware/windows/zipped_exe/32bit'
    file_names = [f for f in os.listdir(path) if f.endswith(('.dll', '.exe'))]
    data = []
    output_dir = '/home/remnux/Downloads/ransomware/windows/zipped_exe/32bit/output14'

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for file_name in file_names:
        result = process_file(file_name, path, output_dir)
        if result:
            data.append(result)
        print(f"all writing done\n")
    df = pd.DataFrame(data)
    df.to_csv(os.path.join(output_dir, 'opcodes2.csv'), index=False)

    
sys.stdout.reconfigure(encoding='utf-8')
initial_analysis()
