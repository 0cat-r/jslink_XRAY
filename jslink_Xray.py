# !/usr/bin/python3
# coding: utf-8
import subprocess
import requests
import warnings
import queue
from fake_useragent import UserAgent

targets_queue = queue.Queue()


def init_output():
    with open(".//output.txt", 'a')as f:
        f.truncate(0)


def init_queue():
    with open(".//output.txt", 'r')as req_f:
        for req in req_f:
            targets_queue.put(req)


def send_xray():
    while not targets_queue.empty():
        if targets_queue.qsize() == 0:
            continue
        print("待扫描的数量为: " + str(targets_queue.qsize()))
        req = targets_queue.get()
        proxies = {
        'http': 'http://127.0.0.1:7777',
        'https': 'http://127.0.0.1:7777',
        }
        try:
            requests.packages.urllib3.disable_warnings()
            ua = UserAgent()
            headers = {'User-Agent': ua.random}
            a = requests.get(req, headers=headers, proxies=proxies, timeout=30, verify=False)
        except:
            continue
    return


def main(target):
    cmd = ["D:\\python3.8.2\\python3.exe", "jslink.py", "-i", target, "-d"]
    open_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    cmd_out = open_process.stdout.read()
    open_process.stdout.close()
    cmd_err = open_process.stderr.read()
    open_process.stderr.close()
    print("[+]--------"+"正在分析  "+target)
    print(cmd_out.decode(errors='ignore'))
    print(cmd_err.decode(errors='ignore'))
    print("[+]--------分析完成，结果已保存至output.txt")
    init_queue()
    send_xray()


if __name__ == '__main__':
    print("""
     __       .__  .__        __         ____  _____________    _____ _____.___.
    |__| _____|  | |__| ____ |  | __     \   \/  /\______   \  /  _  \\__  |   |
    |  |/  ___/  | |  |/    \|  |/ /      \     /  |       _/ /  /_\  \/   |   |
    |  |\___ \|  |_|  |   |  \    <       /     \  |    |   \/    |    \____   |
/\__|  /____  >____/__|___|  /__|_ \_____/___/\  \ |____|_  /\____|__  / ______|
\______|    \/             \/     \/_____/     \_/        \/         \/\/       
        
    author: 0cat
    version: 1.0
    Github: https://github.com/0cat-r/jslink_XRAY        
        """)
    init_output()
    targets = open("targets.txt")
    for target in targets.readlines():
        target = target.strip('\n')
        main(target)




