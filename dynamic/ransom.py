#!/usr/bin/env python3
#python malware.py -a
from __future__ import print_function
import os
import frida
import psutil
import time
from functools import partial
import argparse
import sys


def checkIfProcessRunning(processName):
    for proc in psutil.process_iter():
        try:
            if processName.lower() in proc.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False

def on_message(message, data, exe_dosya_adı):
    file_name = exe_dosya_adı + '.txt'

    if not os.path.exists(file_name):
        with open(file_name, 'w') as f:
            pass

    if 'payload' in message:
        payload = message['payload']
        value = None
        
        if 'func' in payload:
            value = payload['func']
        elif 'hook' in payload:
            value = payload['hook']
        
        if value:
            with open(file_name, 'a') as f:
                f.write(value + ' ')

    print(message)

import os
import time
import frida
import subprocess
from functools import partial

def force_kill(process_name):
    try:
        subprocess.run(["taskkill", "/F", "/IM", process_name], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[+] {process_name} zorla kapatıldı!")
    except subprocess.CalledProcessError:
        print(f"[-] {process_name} kapatılamadı veya zaten kapalı!")

def load_frida(sample, js):
    file_extension = os.path.splitext(sample)[1]
    session = None

    try:
        process_name = os.path.basename(sample)  

        if file_extension == '.exe':
            if checkIfProcessRunning(process_name):
                print(f'[+] Process is running: {process_name}')
                frida.kill(process_name)
                session = frida.spawn(process_name)
                session = frida.attach(session) if session else None  # Attach kontrolü
            else:
                print(f'[+] Running process: {process_name}')
                session = frida.spawn(process_name)
                session = frida.attach(session) if session else None  # Attach kontrolü
        
        if session is None:
            print(f"[-] Frida oturumu oluşturulamadı! {process_name} başlatılamıyor.")
            return

        script = session.create_script(js)
        script.on('message', partial(on_message, exe_dosya_adı=sample))
        script.load()
        frida.resume(process_name)

        time.sleep(15)
        force_kill(process_name)
        frida.kill(process_name)

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        if session is not None:
            force_kill(process_name)
            frida.kill(process_name)



def dump(sample):
    with open("jsscripts\\page_protect.js") as f:
        js = f.read()
    load_frida(sample, js)

def getproc(sample):
    with open("jsscripts\\get_process.js") as f:
        js = f.read()
    load_frida(sample, js)

def mutex(sample):
    with open("jsscripts\\mutex.js") as f:
        js = f.read()
    load_frida(sample, js)

def registry(sample):
    with open("jsscripts\\registry.js") as f:
        js = f.read()
    load_frida(sample, js)

def internet(sample):
    with open("jsscripts\\internet.js") as f:
        js = f.read()
    load_frida(sample, js)

def wscript(sample):
    with open("jsscripts\\net_and_shellt.js") as f:
        js = f.read()
    load_frida(sample, js)

def fileactivity(sample):
    with open("jsscripts\\file_modif.js") as f:
        js = f.read()
    load_frida(sample, js)

def allscripts(sample):
    path = "jsscripts\\"
    js = ''
    for filename in os.listdir(path):
        if filename.endswith('.js'):
            with open(os.path.join(path, filename), 'r') as f:
                js += f.read()
    load_frida(sample, js)

def main(): 
    folder_path = r'C:\Users\BUŞRA'

    tasks = {
        'dump': False,
        'getproc': False,
        'mutex': False,
        'registry': False,
        'internet': False,
        'fileactivity': False,
        'wscript': False,
        'allscripts': True
    }

    for file_name in os.listdir(folder_path):
        sample_file = os.path.join(folder_path, file_name)

        if tasks['dump']:
            dump(sample_file)
        elif tasks['getproc']:
            getproc(sample_file)
        elif tasks['mutex']:
            mutex(sample_file)
        elif tasks['registry']:
            registry(sample_file)
        elif tasks['internet']:
            internet(sample_file)
        elif tasks['fileactivity']:
            fileactivity(sample_file)
        elif tasks['wscript']:
            wscript(sample_file)
        elif tasks['allscripts']:
            allscripts(sample_file)

if __name__ == '__main__':
    main()

