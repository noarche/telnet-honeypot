import socket
import threading
import argparse
import time
import configparser
import sys
import os
from datetime import datetime, timedelta
from colorama import init, Fore, Style

init(autoreset=True)

LOG_FILE = "./telnet.log.txt"
LOG_RETENTION_DAYS = 7


def load_config():
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config


def printc(text, color=Fore.CYAN, verbose=False, is_verbose=False):
    if verbose or is_verbose:
        print(color + text + Style.RESET_ALL)


def log_connection(ip, username):
    now = datetime.utcnow().isoformat()
    line = f"{now} - IP: {ip} - USER: {username}\n"
    with open(LOG_FILE, "a") as f:
        f.write(line)


def prune_old_logs():
    if not os.path.exists(LOG_FILE):
        return

    cutoff = datetime.utcnow() - timedelta(days=LOG_RETENTION_DAYS)
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    with open(LOG_FILE, "w") as f:
        for line in lines:
            try:
                timestamp = datetime.fromisoformat(line.split(" - ")[0])
                if timestamp > cutoff:
                    f.write(line)
            except Exception:
                continue  # skip malformed lines


def handle_client(conn, addr, config, is_verbose):
    motd = config['server']['motd'].replace("\\n", "\n")
    prompt_user = config['prompt']['username']
    prompt_pass = config['prompt']['password']
    loading_text = config['style']['loading_text']
    loading_interval = float(config['style']['loading_dots_interval'])

    ip = addr[0]
    printc(f"[+] Connection from {ip}", Fore.GREEN, True, is_verbose)

    try:
        conn.sendall(motd.encode() + b"\n\n")
        conn.sendall(prompt_user.encode())
        username = recv_line(conn)
        conn.sendall(prompt_pass.encode())
        password = recv_line(conn)

        log_connection(ip, username)
        printc(f"[>] Logged credentials from {ip} - {username}", Fore.YELLOW, True, is_verbose)

        # Simulate eternal loading
        conn.sendall(b"\n" + loading_text.encode())
        dots = ""
        while True:
            dots += "."
            if len(dots) > 3:
                dots = "."
                conn.sendall(b"\r" + loading_text.encode())
            else:
                conn.sendall(b".")
            time.sleep(loading_interval)

    except Exception as e:
        printc(f"[!] Error with {ip}: {e}", Fore.RED, True, is_verbose)
    finally:
        conn.close()
        printc(f"[-] Disconnected {ip}", Fore.MAGENTA, True, is_verbose)


def recv_line(conn):
    data = b""
    while not data.endswith(b"\n"):
        byte = conn.recv(1)
        if not byte:
            break

        # Strip Telnet negotiation bytes (0xFF and following)
        if byte == b'\xff':
            # Skip the next two bytes (Telnet command and option)
            conn.recv(2)
            continue

        data += byte

    return data.decode(errors="ignore").strip()



def start_server(config, is_verbose):
    host = config['server']['host']
    port = int(config['server']['port'])

    prune_old_logs()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        printc(f"[+] Listening on {host}:{port}", Fore.CYAN, True, is_verbose)

        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr, config, is_verbose), daemon=True).start()


def main():
    parser = argparse.ArgumentParser(
        description="Eternal Server - Telnet trap that never ends.",
        add_help=False
    )
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
    parser.add_argument('-h', '--help', action='store_true', help="Show help and exit")
    args = parser.parse_args()

    if args.help:
        parser.print_help()
        sys.exit(0)

    config = load_config()
    try:
        start_server(config, args.verbose)
    except KeyboardInterrupt:
        printc("\n[!] Server shut down by user", Fore.RED, True, True)



if __name__ == "__main__":
    main()
