#!/usr/bin/env python3
"""
crypt.py — single-line smooth progress encrypt/decrypt (archive+encrypt and decrypt+extract merged)
Version 2.3.4
"""
import os
import sys
import time
import getpass
import shutil
import tarfile
import tempfile
import subprocess
import argparse
import threading
from pathlib import Path

VERSION = "2.3.4"
SPINNER = ['-', '\\', '|', '/']

class Colors:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    NC = "\033[0m"

# ---------- utilities ----------
def format_size(b):
    for unit in ('B','KB','MB','GB','TB'):
        if b < 1024:
            return f"{b:.2f} {unit}"
        b /= 1024
    return f"{b:.2f} PB"

def safe_input_password(prompt, show):
    if show:
        return input(prompt)
    else:
        return getpass.getpass(prompt)

def print_line(stage, pct, spinner=' '):
    pct = max(0.0, min(100.0, pct))
    width = 36
    filled = int((pct/100.0) * width)
    bar = '█'*filled + '-'*(width - filled)
    sys.stderr.write(f"\r{Colors.YELLOW}[{stage}] |{bar}| {pct:6.2f}% {spinner}{Colors.NC}")
    sys.stderr.flush()

# ---------- smooth progress helper ----------
def smooth_progress(stage, work_fn, observe_path=None, observe_total=None, est_seconds=1.0):
    spinner_i = 0
    start_time = time.time()
    done_event = threading.Event()
    exc = [None]

    def run_work():
        try:
            work_fn()
        except Exception as e:
            exc[0] = e
        finally:
            done_event.set()

    thread = threading.Thread(target=run_work)
    thread.start()

    pct = 0.0
    observed_max = 0.0
    while not done_event.is_set():
        if exc[0]:
            raise exc[0]

        elapsed = time.time() - start_time
        time_frac = min(1.0, elapsed / est_seconds)
        obs_prog = 0.0
        if observe_path and observe_total:
            try:
                if observe_path.exists():
                    obs = observe_path.stat().st_size
                    obs_frac = min(1.0, obs / observe_total)
                    if obs_frac > observed_max:
                        observed_max = obs_frac
                    obs_prog = observed_max
            except:
                pass
        fraction = obs_prog if obs_prog > 0.0 else time_frac
        pct = fraction
        spinner_i += 1
        print_line(stage, pct * 100, SPINNER[spinner_i % len(SPINNER)])
        time.sleep(0.02)

    if exc[0]:
        raise exc[0]

    print_line(stage, 100.0, ' ')
    sys.stderr.write("\n")
    thread.join()

# ---------- main encryption/decryption implementations ----------
def check_deps_or_exit():
    for cmd in ('openssl','tar'):
        if shutil.which(cmd) is None:
            print(f"{Colors.RED}Missing dependency: {cmd}{Colors.NC}", file=sys.stderr)
            sys.exit(1)

def get_password(purpose, show=False):
    while True:
        prompt = f"{Colors.BLUE}Enter password for {purpose}:{Colors.NC} "
        pwd = safe_input_password(prompt, show)
        if not pwd:
            print(f"{Colors.RED}Password cannot be empty{Colors.NC}", file=sys.stderr)
            continue
        if purpose == "encryption":
            confirm = safe_input_password(f"{Colors.BLUE}Confirm password:{Colors.NC} ", show)
            if pwd != confirm:
                print(f"{Colors.RED}Passwords do not match{Colors.NC}", file=sys.stderr)
                continue
        return pwd

def encrypt(path_str, show=False, output=None):
    p = Path(path_str)
    if not p.exists():
        print(f"{Colors.RED}Not found: {p}{Colors.NC}", file=sys.stderr)
        sys.exit(1)

    password = get_password("encryption", show)
    original_size = p.stat().st_size if p.is_file() else sum(f.stat().st_size for f in p.rglob('*') if f.is_file())

    if output:
        outp = Path(output if output.endswith('.enc') else output + '.enc')
    else:
        outp = p.with_suffix(p.suffix + '.enc')

    if p.is_dir():
        files = [f for f in p.rglob('*') if f.is_file()]
        total_files = len(files)
        temp_tar = tempfile.NamedTemporaryFile(delete=False)
        temp_tar_path = Path(temp_tar.name)
        temp_tar.close()

        # Phase 1: Archiving
        def archive_work():
            with tarfile.open(temp_tar_path, 'w:gz') as tar:
                for f in files:
                    tar.add(f, arcname=p.name + '/' + f.relative_to(p).as_posix())

        size_mb = original_size / (1024 * 1024)
        est_archive = max(1.0, 0.05 * total_files + 0.02 * size_mb)
        observe_total = original_size * 1.1
        smooth_progress("Archiving", archive_work, observe_path=temp_tar_path, observe_total=observe_total, est_seconds=est_archive)

        # Phase 2: Encrypting
        def encrypt_work():
            cmd = ['openssl', 'aes-256-cbc', '-salt', '-pbkdf2', '-iter', '10000',
                   '-in', str(temp_tar_path), '-out', str(outp), '-pass', f'pass:{password}']
            proc = subprocess.run(cmd, check=True, stderr=subprocess.PIPE)

        est_encrypt = max(1.0, 0.1 * size_mb)
        observe_total = temp_tar_path.stat().st_size * 1.05 if temp_tar_path.exists() else 1
        smooth_progress("Encrypting", encrypt_work, observe_path=outp, observe_total=observe_total, est_seconds=est_encrypt)

        # Cleanup
        temp_tar_path.unlink(missing_ok=True)
        shutil.rmtree(p, ignore_errors=True)

        if outp.exists():
            print(f"{Colors.GREEN}Encryption successful: {outp}{Colors.NC}", file=sys.stderr)
            print(f"Original Size: {format_size(original_size)}")
            print(f"Encrypted Size: {format_size(outp.stat().st_size)}")
        else:
            print(f"{Colors.RED}Encryption failed or output missing{Colors.NC}", file=sys.stderr)
            sys.exit(1)

    else:
        # Single file encryption
        def encrypt_work():
            cmd = ['openssl', 'aes-256-cbc', '-salt', '-pbkdf2', '-iter', '10000',
                   '-in', str(p), '-out', str(outp), '-pass', f'pass:{password}']
            proc = subprocess.run(cmd, check=True, stderr=subprocess.PIPE)

        size_mb = p.stat().st_size / (1024 * 1024)
        est = max(1.0, 0.1 * size_mb)
        observe_total = p.stat().st_size * 1.05
        smooth_progress("Encrypting", encrypt_work, observe_path=outp, observe_total=observe_total, est_seconds=est)

        p.unlink(missing_ok=True)

        if outp.exists():
            print(f"{Colors.GREEN}Encryption successful: {outp}{Colors.NC}", file=sys.stderr)
            print(f"Original Size: {format_size(original_size)}")
            print(f"Encrypted Size: {format_size(outp.stat().st_size)}")
        else:
            print(f"{Colors.RED}Encryption failed or output missing{Colors.NC}", file=sys.stderr)
            sys.exit(1)

def decrypt(path_str, show=False):
    p = Path(path_str)
    if not p.exists():
        print(f"{Colors.RED}Not found: {p}{Colors.NC}", file=sys.stderr)
        sys.exit(1)

    temp_out = p.with_suffix(f".tmp.{os.getpid()}")
    original_size = p.stat().st_size

    for attempt in range(1, 4):
        if not p.exists():
            print(f"{Colors.RED}Input file {p} no longer exists{Colors.NC}", file=sys.stderr)
            sys.exit(1)

        password = get_password("decryption", show)

        # Phase 1: Decrypting
        def decrypt_work():
            cmd = ['openssl', 'aes-256-cbc', '-d', '-salt', '-pbkdf2', '-iter', '10000',
                   '-in', str(p), '-out', str(temp_out), '-pass', f'pass:{password}']
            try:
                proc = subprocess.run(cmd, check=True, stderr=subprocess.PIPE, text=True)
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"openssl failed (wrong password or corrupt file): {e.stderr}")

        size_mb = original_size / (1024 * 1024)
        est_dec = max(1.0, 0.1 * size_mb)
        observe_total = original_size * 0.95
        try:
            smooth_progress("Decrypting", decrypt_work, observe_path=Path(temp_out), observe_total=observe_total, est_seconds=est_dec)
        except Exception as e:
            if Path(temp_out).exists():
                Path(temp_out).unlink(missing_ok=True)
            print(f"{Colors.RED}Decryption error: {str(e)}{Colors.NC}", file=sys.stderr)
            continue

        if not Path(temp_out).exists():
            print(f"{Colors.RED}Decrypted output missing — likely wrong password or corrupt file{Colors.NC}", file=sys.stderr)
            continue

        try:
            if tarfile.is_tarfile(temp_out):
                # Phase 2: Extracting
                def extract_work():
                    with tarfile.open(temp_out, 'r:gz') as tar:
                        for member in tar.getmembers():
                            tar.extract(member, path='.', filter='tar')

                est_extract = max(1.0, 0.05 * size_mb)
                smooth_progress("Extracting", extract_work, est_seconds=est_extract)

                # Store members before deleting temp_out
                with tarfile.open(temp_out, 'r:gz') as tar:
                    members = tar.getmembers()

                # Cleanup after successful extraction
                Path(temp_out).unlink(missing_ok=True)
                p.unlink(missing_ok=True)

                # Compute final size
                first_name = members[0].name if members else ''
                top_folder = first_name.split('/')[0] if '/' in first_name else None
                if top_folder and Path(top_folder).exists():
                    final_size = sum(f.stat().st_size for f in Path(top_folder).rglob('*') if f.is_file())
                else:
                    final_size = sum(f.stat().st_size for f in Path('.').rglob('*') if f.is_file())

                print(f"{Colors.GREEN}Decryption successful: folder extracted{Colors.NC}")
                print(f"Original Size: {format_size(original_size)}")
                print(f"Decrypted Size: {format_size(final_size)}")
                return
            else:
                out_file = p.with_suffix('')
                shutil.move(temp_out, out_file)
                p.unlink(missing_ok=True)
                final_size = out_file.stat().st_size
                print(f"{Colors.GREEN}Decryption successful: {out_file}{Colors.NC}")
                print(f"Original Size: {format_size(original_size)}")
                print(f"Decrypted Size: {format_size(final_size)}")
                return
        except Exception as e:
            if Path(temp_out).exists():
                Path(temp_out).unlink(missing_ok=True)
            print(f"{Colors.RED}Error processing decrypted data: {str(e)}{Colors.NC}", file=sys.stderr)
            continue

    print(f"{Colors.RED}Max attempts reached. Decryption failed.{Colors.NC}", file=sys.stderr)
    sys.exit(1)

# ---------- CLI ----------
def main():
    check_deps_or_exit()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-e','--encrypt', action='store_true')
    parser.add_argument('-d','--decrypt', action='store_true')
    parser.add_argument('-o','--output', type=str)
    parser.add_argument('-s','--show', action='store_true')
    parser.add_argument('input_file', nargs='?')
    args = parser.parse_args()
    
    if not args.input_file:
        print(f"Secure File Encryptor/Decryptor v{VERSION}")
        print("Usage: crypt [-e] [-d] [-o output.enc] [-s] <file_or_folder>")
        sys.exit(0)
    
    try:
        if args.decrypt:
            decrypt(args.input_file, show=args.show)
        else:
            encrypt(args.input_file, show=args.show, output=args.output)
    except KeyboardInterrupt:
        sys.stderr.write(f"\n{Colors.RED}Operation cancelled by user.{Colors.NC}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
