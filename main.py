from __future__ import annotations

from colorama import init as colorama_init, Fore, Style
import sys, time, os


#------shells automater--------#
def gen_shellcode():

    os.system('./shell_prep.sh')

def gen_listener():

    os.system('./listener_prep.sh')
#--------ceaser----------#
def ceaser():
    from colorama import Fore, Style, init
    init(autoreset=True)

    def caesar_encrypt(text, shift):
        encrypted = ""
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                encrypted += chr((ord(char) - base + shift) % 26 + base)
            else:
                encrypted += char
        return encrypted

    def caesar_decrypt(text, shift):
        return caesar_encrypt(text, -shift)

    def Ceaser():
        print(Fore.CYAN + Style.BRIGHT + "\n--- Caesar Cipher Tool ---\n")
        print(Fore.YELLOW + "Choose an option:")
        print(Fore.GREEN + "1. Encrypt Text")
        print(Fore.MAGENTA + "2. Decrypt Text")

        choice = input(Fore.BLUE + "\nEnter 1 or 2: ").strip()

        if choice == '1':
            plain_text = input(Fore.WHITE + "\nEnter text to encrypt: ")
            try:
                shift = int(input(Fore.WHITE + "Enter shift amount (0-25): "))
                encrypted = caesar_encrypt(plain_text, shift)
                print(Fore.GREEN + "\nEncrypted Text:\n" + Fore.CYAN + encrypted)
            except ValueError:
                print(Fore.RED + "Shift must be a number!")

        elif choice == '2':
            cipher_text = input(Fore.WHITE + "\nEnter text to decrypt: ")
            try:
                shift = int(input(Fore.WHITE + "Enter shift amount (0-25): "))
                decrypted = caesar_decrypt(cipher_text, shift)
                print(Fore.GREEN + "\nDecrypted Text:\n" + Fore.CYAN + decrypted)
            except ValueError:
                print(Fore.RED + "Shift must be a number!")
        elif choice == '3':
            os.system('clear')
            print(Fore.MAGENTA + LOGO2 + Style.RESET_ALL)
            main()
        else:
            print(Fore.RED + "\nInvalid choice. Please enter 1 or 2.")
            Ceaser()

    Ceaser()

#_________iplocater______________#
def iplocate():
    import ipapi
    from colorama import init as colorama_init, Fore, Style
    logo = r"""
    ╔═══════════════════════════════════════════════════════════╗
    ║  ░█▄█░█▀█░█▀█░█▀▄  OSINT TOOLKIT. By Duncan Kinyua (Acid) ║
    ║  ░█▀█░█▄█░█▄█░█▄▀             IP-TRACKER                  ║
    ╚═══════════════════════════════════════════════════════════╝
    """

    print(logo)

    def program():

        ip = input(Fore.MAGENTA+ "Enter target ip: " )
        location = ipapi.location(ip)

        for k , v in location.items():
            print(Fore.YELLOW + k + " : " + str(v))

    yes = ['y' , 'yes']
    no = ['n' , 'no']

    cont = ""
    while cont not in no:
        program()
        cont = input(Fore.RED + "Do you want to continue? [y/n]")
        if cont in no:
            os.system('clear')
            print(Fore.CYAN + LOGO2 + Style.RESET_ALL)
            main()
        else:
            iplocate()
#---------binary interprator---------#
def binary():
    from colorama import Fore, Back, Style, init
    init(autoreset=True)

    def text_to_binary(text):
        binary = ' '.join(format(ord(char), '08b') for char in text)
        return binary

    def binary_to_text(binary):
        try:
            chars = binary.split()
            text = ''.join(chr(int(char, 2)) for char in chars)
            return text
        except ValueError:
             return Fore.RED + "Invalid binary input!"

    def inter():
        print(Fore.CYAN + Style.BRIGHT + "\n--- Binary ↔ Text Converter ---\n")

        print(Fore.YELLOW + "Choose an option:")
        print(Fore.GREEN + "1. Text to Binary")
        print(Fore.MAGENTA + "2. Binary to Text")
        print(Fore.MAGENTA + "3. Exit")

        choice = input(Fore.BLUE + "\nEnter 1 or 2 or 3: ").strip()

        if choice == '1':
            user_input = input(Fore.WHITE + "\nEnter text to convert to binary: ")
            binary_result = text_to_binary(user_input)
            print(Fore.GREEN + "\nBinary Result:\n" + Fore.CYAN + binary_result)

        elif choice == '2':
            user_input = input(Fore.WHITE + "\nEnter binary to convert to text (space-separated 8-bit): ")
            text_result = binary_to_text(user_input)
            print(Fore.GREEN + "\nText Result:\n" + Fore.CYAN + text_result)
        
        elif choice == '3':
            os.system('clear')
            print(Fore.CYAN + LOGO2 + Style.RESET_ALL)
            main()
        else:
            print(Fore.RED + "\nInvalid choice. Please enter 1 or 2.")
            inter()

    if __name__ == "__main__":
        inter()


#----------netdiscover--------------#
def net():
    import argparse
    import subprocess
    import shutil
    import sys
    import re
    import csv
    import json
    import os
    from datetime import datetime
    from pathlib import Path

    # Simple regex for lines like:
    # 192.168.1.1  00:11:22:33:44:55  1  (vendor)
    IP_MAC_LINE_RE = re.compile(
        r'^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f:]{17})\s+(\d+)\s+(.*\S)\s*$'
    )

    def hood_logo() -> str:
        """Return ASCII art for HOOD SCANNER."""
        return r"""
    ╔═══════════════════════════════════════════════════════════╗
    ║  ░█▄█░█▀█░█▀█░█▀▄  SCANNER.       By Duncan Kinyua (Acid) ║
    ║  ░█▀█░█▄█░█▄█░█▄▀ scan for IPs using netdiscover          ║
    ╚═══════════════════════════════════════════════════════════╝
                                                                        
                     HOOD SCANNER
        """.strip("\n")

    def check_requirements():
        if shutil.which("netdiscover") is None:
            print(Fore.RED + "Error: 'netdiscover' not found in PATH. Install it (e.g. apt install netdiscover) and try again.", file=sys.stderr)
            sys.exit(2)

    def run_netdiscover(range_cidr: str, interface: str | None, timeout: int | None):
        cmd = ["netdiscover", "-r", range_cidr, "-P"]  # -P run in passive? (keeps output format consistent) ; remove if you want active scanning
        if interface:
           cmd += ["-i", interface]
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}Error: netdiscover timed out after {timeout} seconds.", file=sys.stderr)
            return None, None
        except PermissionError:
            print(Fore.YELLOW + "Permission denied: you probably need to run this script with sudo/root.", file=sys.stderr)
            return None, None

        return completed.returncode, completed.stdout

    def parse_netdiscover_output(output: str):
        results = []
        for line in output.splitlines():
            m = IP_MAC_LINE_RE.match(line)
            if m:
                ip, mac, count, vendor = m.group(1), m.group(2).lower(), m.group(3), m.group(4).strip()
                results.append({
                    "ip": ip,
                    "mac": mac,
                    "count": int(count),
                    "vendor": vendor
                })
        return results

    def save_outputs(results, raw_output, out_prefix, logo_text):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        raw_file = f"{out_prefix}_{ts}.txt"
        csv_file = f"{out_prefix}_{ts}.csv"
        json_file = f"{out_prefix}_{ts}.json"

        header = f"{logo_text}\n\nHOOD SCANNER - scan time: {datetime.now().isoformat()}\n\n--- RAW netdiscover OUTPUT BELOW ---\n\n"

        # Save raw (with logo header)
        with open(raw_file, "w", encoding="utf-8") as f:
            f.write(header)
            f.write(raw_output or "")

        # Save CSV
        with open(csv_file, "w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "mac", "count", "vendor"])
            writer.writeheader()
            for r in results:
                writer.writerow(r)

        # Save JSON
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump({
                "timestamp": ts,
                "scan_time_iso": datetime.now().isoformat(),
                "count": len(results),
                "results": results
            }, f, indent=2)

        return raw_file, csv_file, json_file

    def run():
        parser = argparse.ArgumentParser(description="Run netdiscover and save results to files (with HOOD SCANNER ASCII logo).")
        parser.add_argument("-r", "--range", default="192.168.1.0/24", help="Target network range (CIDR). Default: 192.168.1.0/24")
        parser.add_argument("-i", "--interface", default=None, help="Network interface to use (optional).")
        parser.add_argument("-t", "--timeout", type=int, default=60, help="Timeout for netdiscover in seconds (default 60).")
        parser.add_argument("-o", "--out-prefix", default="netdiscover_results", help="Output filename prefix (default netdiscover_results).")
        parser.add_argument("--no-check-root", action="store_true", help="Skip warning about not running as root.")
        parser.add_argument("--no-logo", action="store_true", help="Do not print/write ASCII logo.")
        args = parser.parse_args()

        check_requirements()

        if not args.no_check_root:
            try:
                if hasattr(os, "geteuid") and os.geteuid() != 0:
                    print(Fore.RED + "Warning: it's recommended to run this script as root (sudo) for ARP scanning to work correctly.", file=sys.stderr)
            except Exception:
                pass

        logo_text = "" if args.no_logo else hood_logo()
        if logo_text:
            print(Fore.CYAN + logo_text + Style.RESET_ALL)
            print()

        print(f"{Fore.GREEN}Running netdiscover on {args.range} ... (timeout {args.timeout}s)")
        retcode, out = run_netdiscover(args.range, args.interface, args.timeout)
        if out is None:
            print(Fore.RED + "No output from netdiscover.", file=sys.stderr)
            os.system('clear')
            print(Fore.YELLOW + LOGO2 + Style.RESET_ALL)
            main()

        results = parse_netdiscover_output(out)
        raw_file, csv_file, json_file = save_outputs(results, out, args.out_prefix, logo_text)

        print(f"\nSaved raw output to: {raw_file}")
        print(f"Saved parsed CSV to: {csv_file}")
        print(f"Saved parsed JSON to: {json_file}")
        print(f"Found {len(results)} host(s). Example entries:")
        for r in results[:10]:
            print(f"  {r['ip']}  {r['mac']}  count={r['count']}  vendor='{r['vendor']}'")

    if __name__ == "__main__":
        run()
#-------------watchdog----------#
def watch():
    import psutil, time, hashlib, json, os, subprocess, sys, shutil, shlex
    from datetime import datetime
    import random, atexit, signal, threading
    from colorama import init as colorama_init, Fore, Style

    OUTPUT_DIR = os.path.abspath("hw_output")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

# -------------------------
# ASCII logos (choose randomly)
# -------------------------
    LOGOS = [
    r"""
          ╔════════════════════════════════╗
          ║     W A T C H D O G   P R O    ║
          ║  Cybersecurity Threat Monitor  ║
          ║   by Duncan kinyua  *Acid*     ║
          ╚════════════════════════════════╝
                    [o  o]
                    | -- |
                   /|____|\
                  /_/    \_\
    """,
    r"""
             W A T C H D O G  -  P R O
         Real-time Host Intrusion Monitor
             Duncan kinyua   *Acid*
    """,
    r"""
[ WATCHDOG ] 
>by Duncan kinyua *Acid*
━━━━━━━━━━━━━━━━━━━━━━━━━━
> Intrusion Detection Tool
> Monitoring Suspicious Activity    
> Logging Remote Connections
> Capturing PCAP Evidence
━━━━━━━━━━━━━━━━━━━━━━━━━━
>>> INITIATED... █▓▒░ 
    """,
    r"""
          /\_____/\
         /  o   o  \
        ( ==  ^  == )
         )         (
        (           )
       ( (  )   (  ) )
      (__(__)___(__)__)

     W A T C H D O G   —   DEFENSE INITIATED
         Duncan Kinyua   *Acid*
    """
    ]


    def show_banner():
        banner = random.choice(LOGOS)
        print(Fore.CYAN + banner)
        sys.stdout.flush()

# -------------------------
# The rest of the PoC
# -------------------------
    SYSTEM_WHITELIST = {
        "system", "systemd", "explorer.exe", "svchost.exe", "lsass.exe",
        "init", "kernel_task", "launchd", "bash", "zsh", "python", "python3"
    }

    def file_sha256(path, block_size=65536):
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for block in iter(lambda: f.read(block_size), b""):
                    h.update(block)
            return h.hexdigest()
        except Exception:
            return None

    def collect_snapshot():
        ts = datetime.utcnow().isoformat() + "Z"
        procs = []
        for p in psutil.process_iter(['pid','name','exe','cmdline','username','create_time','ppid','cwd', 'status']):
            try:
                info = p.info
                try:
                    conns = p.connections(kind='inet')
                except Exception:
                    conns = []
                conns_s = []
                for c in conns:
                    conns_s.append({
                        "fd": c.fd, "family": str(c.family), "type": str(c.type),
                        "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                        "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                        "status": c.status
                    })
                exe = info.get('exe') or ""
                sha256 = file_sha256(exe) if exe else None
                procs.append({
                    "pid": info.get('pid'),
                    "name": info.get('name'),
                    "ppid": info.get('ppid'),
                    "exe": exe,
                    "cmdline": info.get('cmdline'),
                    "username": info.get('username'),
                    "create_time": info.get('create_time'),
                    "status": info.get('status'),
                    "sha256": sha256,
                    "connections": conns_s
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        net_conns = []
        for c in psutil.net_connections(kind='inet'):
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None
            net_conns.append({
                "pid": c.pid, "fd": c.fd, "laddr": laddr, "raddr": raddr, "status": c.status
            })

        snap = {"timestamp": ts, "processes": procs, "net_connections": net_conns}
        fn = os.path.join(OUTPUT_DIR, f"snapshot_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json")
        with open(fn, "w") as f:
            json.dump(snap, f, indent=2)
        print(f"{Fore.GREEN}[+] Snapshot saved to {fn}")
        return snap

    def score_process(p):
        score = 0
        name = (p.get("name") or "").lower()
        exe = (p.get("exe") or "").lower()
        cmdline = " ".join(p.get("cmdline") or [])
        sha = p.get("sha256")
        if exe and ("temp" in exe.lower() or "/tmp/" in exe.lower()):
            score += 3
        if name not in SYSTEM_WHITELIST and (exe == "" or exe is None):
            score += 2
        for c in p.get("connections", []):
            if c.get("raddr"):
                score += 1
        if exe and sha is None:
            score += 1
        if any(k in cmdline.lower() for k in ["-m", "--server", "nc ", "netcat", "meterpreter", "-e "]):
            score += 3
        return score

    def analyze_snapshot(snap):
        results = []
        for p in snap["processes"]:
            s = score_process(p)
            if s >= 3:
                results.append({"proc": p, "score": s})
        results.sort(key=lambda x: x["score"], reverse=True)
        return results

    def show_findings(findings):
        if not findings:
            print(f"{Fore.GREEN}[*] No high-confidence suspicious processes found.")
            return
        print(f"{Fore.YELLOW}[!] Suspicious processes:")
        for i, f in enumerate(findings, 1):
            p = f["proc"]
            print(f" {i}. PID {p['pid']} | {p['name']} | score={f['score']}")
            print(f"    exe: {p['exe']}")
            print(f"    cmd: {' '.join(p.get('cmdline') or [])}")
            print(f"  user: {p['username']} | started: {p.get('create_time')}")
            if p.get('connections'):
                for c in p['connections']:
                    if c.get('raddr'):
                        print(f"      -> remote {c['raddr']} ({c['status']})")
        print(Style.RESET_ALL)

    def kill_process(pid):
        try:
            p = psutil.Process(pid)
            p.terminate()
            p.wait(timeout=5)
            print(f"[+] Process {pid} terminated")
        except Exception as e:
            print(f"[-] Failed to terminate {pid}: {e}")

    def block_remote_ip(ip):
        if sys.platform.startswith("win"):
            cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    'name=HostWatchdogBlock', f'dir=out', f'action=block', f'remoteip={ip}']
        else:
            cmd = ['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP']
        try:
            print(f"[+] Running: {' '.join(cmd)}")
            subprocess.check_call(cmd)
            print("[+] Firewall rule added (may require admin).")
        except Exception as e:
            print(f"[-] Could not add firewall rule: {e}")

    def export_findings(findings):
        fn = os.path.join(OUTPUT_DIR, f"findings_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json")
        with open(fn, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"[+] Findings exported to {fn}")

# --------------------------
# pcap capture utilities
# --------------------------
    def get_default_interface():
        try:
            for name, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if getattr(a, 'family', None) and str(a.family).lower().find('inet') != -1:
                        if not name.lower().startswith("lo") and not name.lower().startswith("loop"):
                            return name
            return next(iter(psutil.net_if_addrs().keys()))
        except Exception:
            return None

    def build_bpf_for_ips(ips):
        ips = list(set(ips))
        if not ips:
            return None
        parts = [f"host {ip}" for ip in ips]
        return " or ".join(parts)

    def program_exists(name):
        from shutil import which
        return which(name) is not None

    def capture_with_tcpdump(filter_bpf, iface, duration, out_path):
        if iface is None:
            iface = "any"
        cmd = ['sudo', 'timeout', str(duration),
                'tcpdump', '-i', iface, '-w', out_path, filter_bpf]
        try:
            if sys.platform == "darwin":
                cmd = ['sudo', 'tcpdump', '-i', iface, '-w', out_path, '-G', str(duration), '-W', '1', filter_bpf]
            print(f"[+] Executing tcpdump: {' '.join(shlex.quote(p) for p in cmd)}")
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception as e:
            print(f"[-] tcpdump capture failed: {e}")
            return False

    def capture_with_dumpcap(filter_bpf, iface, duration, out_path):
        cmd = ['dumpcap']
        if iface:
            cmd += ['-i', iface]
        cmd += ['-a', f'duration:{duration}', '-f', filter_bpf, '-w', out_path]
        try:
            print(f"[+] Executing dumpcap: {' '.join(shlex.quote(p) for p in cmd)}")
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception as e:
            print(f"[-] dumpcap capture failed: {e}")
            return False

    def capture_with_tshark(filter_bpf, iface, duration, out_path):
        cmd = ['tshark']
        if iface:
            cmd += ['-i', iface]
        cmd += ['-a', f'duration:{duration}', '-f', filter_bpf, '-w', out_path]
        try:
            print(f"[+] Executing tshark: {' '.join(shlex.quote(p) for p in cmd)}")
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception as e:
            print(f"[-] tshark capture failed: {e}")
            return False

    def capture_with_scapy(filter_bpf, iface, duration, out_path):
        try:
            from scapy.all import sniff, wrpcap
        except Exception as e:
            print(f"[-] scapy not available: {e}")
            return False
        try:
            print(f"[+] Starting scapy sniff on iface={iface} dur={duration}s filter='{filter_bpf}'")
            pkts = sniff(iface=iface, timeout=duration, filter=filter_bpf)
            if pkts:
                wrpcap(out_path, pkts)
                return True
            else:
                open(out_path, "wb").close()
                return True
        except Exception as e:
            print(f"[-] scapy capture failed: {e}")
            return False

    def capture_pcap_for_ips(ips, duration=15, iface=None):
        if not ips:
            print("[*] No remote IPs provided for capture.")
            return None
        bpf = build_bpf_for_ips(ips)
        if not bpf:
            print("[*] Could not build capture filter.")
            return None
        if iface is None:
            iface = get_default_interface()
        timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        out_path = os.path.join(OUTPUT_DIR, f"capture_{timestamp}.pcap")
        print(f"{Fore.YELLOW}[+] Attempting to capture {duration}s pcap for IPs: {', '.join(ips)}")
        print(f"{Fore.YELLOW}[+] BPF filter: {bpf}")
        if program_exists('tcpdump'):
            ok = capture_with_tcpdump(bpf, iface, duration, out_path)
            if ok:
                print(f"{Fore.GREEN}[+] pcap saved to {out_path} (tcpdump)")
                return out_path
        if program_exists('dumpcap'):
            ok = capture_with_dumpcap(bpf, iface, duration, out_path)
            if ok:
                print(f"{Fore.GREEN}[+] pcap saved to {out_path} (dumpcap)")
                return out_path
        if program_exists('tshark'):
            ok = capture_with_tshark(bpf, iface, duration, out_path)
            if ok:
                print(f"{Fore.GREEN}[+] pcap saved to {out_path} (tshark)")
                return out_path
        ok = capture_with_scapy(bpf, iface, duration, out_path)
        if ok:
            print(f"{Fore.GREEN}[+] pcap saved to {out_path} (scapy)")
            return out_path

        print(f"{Fore.RED}[-] All capture methods failed. Ensure tcpdump/dumpcap/tshark or scapy is installed and run with sufficient privileges.")
        return None

    def gather_remote_ips_from_findings(findings):
        ips = set()
        for f in findings:
            p = f["proc"]
            for c in p.get('connections', []):
                r = c.get('raddr')
                if r:
                    ip = r.split(':')[0]
                    if ip not in ('127.0.0.1', '::1'):
                        ips.add(ip)
        return list(ips)

    def interactive_loop():
        snap = collect_snapshot()
        findings = analyze_snapshot(snap)
        show_findings(findings)
        if not findings:
            print(f"{Fore.GREEN}No high-confidence suspicious processes found. You may still capture recent remote connections.")
        while True:
            print("Choose an action:")
            print(" [1] Save another snapshot")
            print(" [2] Export findings to file")
            print(" [3] Kill a process")
            print(" [4] Block an IP")
            print(" [5] Capture short pcap for suspicious remote IPs (auto)")
            print(" [6] Capture short pcap for arbitrary IPs")
            print(" [7] Quit")
            c = input("action> ").strip()
            if c == "1":
                collect_snapshot()
            elif c == "2":
                export_findings(findings)
            elif c == "3":
                pid = input("PID to kill> ").strip()
                if pid.isdigit():
                    kill_process(int(pid))
                else:
                    print("Invalid PID.")
            elif c == "4":
                ip = input(f"{Fore.YELLOW}remote IP to block> ").strip()
                block_remote_ip(ip)
            elif c == "5":
                ips = gather_remote_ips_from_findings(findings)
                if not ips:
                    print(f"{Fore.RED}[*] No remote IPs found in current findings.")
                else:
                    dur = input(f"{Fore.YELLOW}Duration seconds (default 15)> ").strip() or "15"
                    try:
                        dur = int(dur)
                    except:
                        dur = 15
                    capture_pcap_for_ips(ips, duration=dur)
            elif c == "6":
                raw = input(f"{Fore.YELLOW}Enter comma-separated IPs> ").strip()
                ips = [x.strip() for x in raw.split(",") if x.strip()]
                if not ips:
                    print(f"{Fore.RED}No IPs entered.")
                else:
                    dur = input(f"{Fore.YELLOW}Duration seconds (default 15)> ").strip() or "15"
                    try:
                        dur = int(dur)
                    except:
                        dur = 15
                    capture_pcap_for_ips(ips, duration=dur)
            elif c == "7":
                hprint(f"{Fore.YELLOW}[*] Quitting...")
                main()
            else:
                print(f"{Fore.RED}unknown option")
                main()

    if __name__ == "__main__":
    # Show a random logo at startup
        show_banner()
        print(f"{Fore.MAGENTA}Host Watchdog PoC — monitoring, snapshotting, and pcap capture")
        interactive_loop()
#---------mass scanner------------#
def osint():
    import argparse
    import subprocess
    import os
    import sys
    import datetime
    import shlex
    import xml.etree.ElementTree as ET
    from pathlib import Path
    import time
    import socket
    import threading
    # 3rd party
    try:
        import dns.resolver
        import dns.reversename
        import dns.query
        import dns.zone
    except Exception:
        print("ERROR: dnspython is required (pip install dnspython)")
        raise

    try:
        from colorama import init as colorama_init, Fore, Style
    except Exception:
        print("ERROR: colorama is required (pip install colorama)")
        raise

    # GUI
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox

        TK_AVAILABLE = True
    except Exception:
        TK_AVAILABLE = False

    # Config / defaults
    DEFAULT_NMAP_ARGS = (
        "-sS -sV --top-ports 100 -T4 "
        "--script=banner,http-title")

    #DEFAULT_NMAP_ARGS = "-sV -sC -Pn -sS -T4"
    NMAP_TIMEOUT = 600
    WHOIS_TIMEOUT = 30
    RATE_LIMIT_SECONDS = 0.5
    DNS_TIMEOUT = 5.0
    AXFR_TIMEOUT = 15.0
    BRUTE_THREADS = 10
    BRUTE_RATE = 0.02  # tiny pause per request to avoid blasting

    colorama_init(autoreset=True)

    # small built-in wordlist for demonstration (you'll want a larger file for real work)
    DEFAULT_WORDS = [
        "www", "mail", "ftp", "ns", "api", "dev", "beta", "test", "admin", "smtp",
        "webmail", "vpn", "m", "portal", "secure", "db"
    ]


    def timestamp() -> str:
        return datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


    def sanitize_filename(s: str) -> str:
        return "".join([c if (c.isalnum() or c in "-._") else "_" for c in s])


    def safe_makedirs(path: str):
        Path(path).mkdir(parents=True, exist_ok=True)


    def run_subprocess(cmd: str, timeout: int | None = None):
        try:
            proc = subprocess.run(
                shlex.split(cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as e:
            return 124, "", f"TimeoutExpired: {e}"
        except FileNotFoundError as e:
            return 127, "", f"NotFound: {e}"
        except Exception as e:
            return 1, "", f"Error: {e}"


    ### Pretty logo
    LOGO = r"""
    ╔══════════════════════════════════════════════════════════╗
    ║  ░█▄█░█▀█░█▀█░█▀▄  OSINT TOOLKIT. By Duncan Kinyua (Acid)║
    ║  ░█▀█░█▄█░█▄█░█▄▀       whois + dns + axfr + nmap        ║
    ╚══════════════════════════════════════════════════════════╝
    """


    def print_logo():
        print(Fore.CYAN + Style.BRIGHT + LOGO + Style.RESET_ALL)
        print(
            Fore.MAGENTA
            + " Friendly OSINT helper — active network probing requires explicit permission\n"
            + Style.RESET_ALL
        )


    def cprint_ok(msg: str):
        print(Fore.GREEN + " [+] " + msg + Style.RESET_ALL)


    def cprint_warn(msg: str):
        print(Fore.YELLOW + " [!] " + msg + Style.RESET_ALL)


    def cprint_err(msg: str):
        print(Fore.RED + " [X] " + msg + Style.RESET_ALL)


    ### WHOIS ###
    def run_whois(target: str, outdir: str):
        cprint_ok(f"Running whois for {target}...")
        cmd = f"whois {shlex.quote(target)}"
        rc, out, err = run_subprocess(cmd, timeout=WHOIS_TIMEOUT)
        fn = Path(outdir) / f"whois_{sanitize_filename(target)}_{timestamp()}.txt"
        with open(fn, "w", encoding="utf-8") as f:
            f.write(f"## CMD: {cmd}\n\n")
            f.write(out or "")
            if err:
                f.write("\n\n## STDERR\n")
                f.write(err)
        time.sleep(RATE_LIMIT_SECONDS)
        cprint_ok(f"whois saved to {fn} (rc={rc})")
        return rc, str(fn), out, err


    ### DNS ###
    def query_dns_records(target: str, outdir: str):
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        resolver.timeout = DNS_TIMEOUT
        records: dict[str, list[str]] = {}
        queries = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        cprint_ok(f"Gathering DNS records for {target}...")
        for q in queries:
            try:
                answers = resolver.resolve(target, q)
                lst = [str(r).rstrip(".") for r in answers]
                records[q] = lst
                cprint_ok(f"{q}: {', '.join(lst)}")
            except dns.resolver.NXDOMAIN:
                records[q] = []
                cprint_warn(f"{q}: NXDOMAIN / no data")
            except dns.resolver.NoAnswer:
                records[q] = []
                cprint_warn(f"{q}: NoAnswer")
            except dns.resolver.Timeout:
                records[q] = []
                cprint_warn(f"{q}: Timeout")
            except Exception as e:
                records[q] = []
                cprint_warn(f"{q}: error ({e})")
            time.sleep(0.15)

        # reverse PTRs
        ip_addrs: list[str] = []
        for t in ("A", "AAAA"):
            ip_addrs.extend(records.get(t, []))
        ptrs: dict[str, list[str]] = {}
        for ip in ip_addrs:
            try:
                rev_name = dns.reversename.from_address(ip)
                answers = resolver.resolve(rev_name, "PTR")
                ptrs[ip] = [str(r).rstrip(".") for r in answers]
                cprint_ok(f"PTR {ip} -> {', '.join(ptrs[ip])}")
            except Exception as e:
                ptrs[ip] = []
                cprint_warn(f"PTR {ip}: {e}")
            time.sleep(0.1)

        # save
        fn = Path(outdir) / f"dns_{sanitize_filename(target)}_{timestamp()}.txt"
        with open(fn, "w", encoding="utf-8") as f:
            f.write(f"DNS results for {target}  (queried at {timestamp()} UTC)\n\n")
            for q in queries:
                f.write(f"{q}:\n")
                for item in records.get(q, []):
                    f.write(f"  - {item}\n")
                if not records.get(q):
                    f.write("  - (none)\n")
                f.write("\n")
            if ptrs:
                f.write("PTR lookups:\n")
                for ip, names in ptrs.items():
                    f.write(f"  {ip} -> {', '.join(names) if names else '(none)'}\n")
        cprint_ok(f"DNS saved to {fn}")
        return str(fn), records, ptrs


    ### AXFR (zone transfer) ###
    def attempt_axfr(domain: str, outdir: str, resolver=None):
        resolver = resolver or dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        resolver.timeout = DNS_TIMEOUT
        axfr_results: dict[str, dict] = {}
        cprint_ok(f"Checking NS records for {domain} to attempt AXFR (zone transfer) ...")
        try:
            ns_answers = resolver.resolve(domain, "NS")
            ns_list = [str(r).rstrip(".") for r in ns_answers]
        except Exception as e:
            cprint_warn(f"Cannot fetch NS records: {e}")
            ns_list = []

        cprint_ok(f"Found nameservers: {', '.join(ns_list) if ns_list else '(none)'}")

        for ns in ns_list:
            try:
                # resolve NS hostname to IP (A/AAAA)
                addrs: list[str] = []
                try:
                    a_ans = resolver.resolve(ns, "A")
                    addrs.extend([str(r) for r in a_ans])
                except Exception:
                    pass
                try:
                    a6_ans = resolver.resolve(ns, "AAAA")
                    addrs.extend([str(r) for r in a6_ans])
                except Exception:
                    pass
                if not addrs:
                    cprint_warn(f"Could not resolve {ns} to IP, skipping AXFR attempt.")
                    axfr_results[ns] = {"ips": [], "success": False, "error": "no IP", "zone": None}
                    continue

                # try AXFR for each ip on port 53 TCP
                success = False
                axfr_zone = None
                last_error = None
                for ip in addrs:
                    cprint_ok(f"Attempting AXFR against {ns} ({ip}) ...")
                    try:
                        xfr = dns.query.xfr(where=ip, zone=domain, timeout=AXFR_TIMEOUT)
                        z = dns.zone.from_xfr(xfr)
                        if z is not None:
                            success = True
                            axfr_zone = z
                            try:
                                # len(list(z)) may be expensive; just log node count if available
                                node_count = len(list(z.nodes)) if hasattr(z, "nodes") else "(unknown)"
                                cprint_ok(f"AXFR successful from {ns} ({ip}) — {node_count} records")
                            except Exception:
                                cprint_ok(f"AXFR successful from {ns} ({ip})")
                            break
                    except Exception as e:
                        last_error = str(e)
                        cprint_warn(f"AXFR attempt {ns} ({ip}) failed: {e}")
                axfr_results[ns] = {"ips": addrs, "success": success, "zone": axfr_zone, "error": last_error}
            except Exception as e:
                axfr_results[ns] = {"ips": [], "success": False, "zone": None, "error": str(e)}

        # Save results
        fn = Path(outdir) / f"axfr_{sanitize_filename(domain)}_{timestamp()}.txt"
        with open(fn, "w", encoding="utf-8") as f:
            f.write(f"AXFR results for {domain}  ({timestamp()} UTC)\n\n")
            for ns, info in axfr_results.items():
                f.write(f"NS: {ns}\n")
                f.write(f"  IPs: {', '.join(info.get('ips', [])) or '(none)'}\n")
                f.write(f"  Success: {info.get('success')}\n")
                if info.get("error"):
                    f.write(f"  Error: {info.get('error')}\n")
                if info.get("zone"):
                    f.write("  Zone records:\n")
                    try:
                        zone = info["zone"]
                        # Attempt to enumerate zone nodes if possible
                        if hasattr(zone, "nodes"):
                            for name, node in zone.nodes.items():
                                f.write(f"    - {name}\n")
                        else:
                            f.write("    (zone object present but cannot enumerate nodes)\n")
                    except Exception:
                        f.write("    (failed to enumerate zone records)\n")
                f.write("\n")
        cprint_ok(f"AXFR summary saved to {fn}")
        return str(fn), axfr_results


    ### Subdomain brute force ###
    def brute_worker(domain: str, q: str, resolver, found_list: list, lock: threading.Lock, stop_event: threading.Event):
        try:
            answers = resolver.resolve(q, "A")
            ips = [str(r) for r in answers]
            with lock:
                found_list.append((q, ips))
                cprint_ok(f"Found: {q} -> {', '.join(ips)}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception:
            # minor noise - timeouts, etc.
            pass


    def brute_subdomains(domain: str, outdir: str, wordlist=None, threads=BRUTE_THREADS, resolver=None):
        resolver = resolver or dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        resolver.timeout = DNS_TIMEOUT
        if wordlist is None:
            words = DEFAULT_WORDS
        else:
            words = list(wordlist)
        total = len(words)
        cprint_ok(f"Starting brute-force for {total} subdomains (threads={threads}) ...")
        found: list[tuple[str, list[str]]] = []
        lock = threading.Lock()
        stop_event = threading.Event()
        qlist = [f"{w}.{domain}" for w in words]
        # simple thread pool
        idx = 0
        active: list[threading.Thread] = []
        while idx < len(qlist):
            # spawn up to threads
            while len(active) < threads and idx < len(qlist):
                qname = qlist[idx]
                t = threading.Thread(target=brute_worker, args=(domain, qname, resolver, found, lock, stop_event), daemon=True)
                t.start()
                active.append(t)
                idx += 1
                time.sleep(BRUTE_RATE)
            # cleanup finished
            active = [t for t in active if t.is_alive()]
            time.sleep(0.01)
        # wait for remaining
        for t in active:
            t.join(timeout=1.0)

        # save results
        fn = Path(outdir) / f"brute_{sanitize_filename(domain)}_{timestamp()}.txt"
        with open(fn, "w", encoding="utf-8") as f:
            f.write(f"Subdomain brute force results for {domain}  (queried at {timestamp()} UTC)\n\n")
            if found:
                for q, ips in found:
                    f.write(f"{q} -> {', '.join(ips)}\n")
            else:
                f.write("(no resolvable subdomains found with provided wordlist)\n")
        cprint_ok(f"Brute-force results saved to {fn} ({len(found)} found)")
        return str(fn), found


    ### NMAP ###
    def prepare_nmap_cmd(target: str, outdir: str, ports=None, extra_args=None):
        extra = extra_args or DEFAULT_NMAP_ARGS
        portpart = f"-p {ports}" if ports else ""
        xml_out = Path(outdir) / f"nmap_{sanitize_filename(target)}_{timestamp()}.xml"
        # ensure xml_out is quoted when building the command
        cmd = f"nmap {extra} {portpart} -oX {shlex.quote(str(xml_out))} {shlex.quote(target)}"
        return cmd, str(xml_out)


    def run_nmap(target: str, outdir: str, ports=None, extra_args=None, do_scan=False):
        cmd, xml_out = prepare_nmap_cmd(target, outdir, ports, extra_args)
        if not do_scan:
            plan_fn = Path(outdir) / f"nmap_plan_{sanitize_filename(target)}_{timestamp()}.txt"
            with open(plan_fn, "w", encoding="utf-8") as f:
                f.write("## NMAP DRY RUN (no scan performed)\n")
                f.write(f"## Command that would be run:\n{cmd}\n\n")
                f.write("## Notes:\n- Provide --confirm (CLI) or check the confirmation box in GUI to perform active scan.\n")
                f.write(f"- Default args: {DEFAULT_NMAP_ARGS}\n")
            cprint_warn(f"Nmap dry-run saved to {plan_fn}")
            return 0, str(plan_fn), cmd, None

        cprint_ok(f"Executing nmap (active scan) ...")
        rc, out, err = run_subprocess(cmd, timeout=NMAP_TIMEOUT)
        raw_out = Path(outdir) / f"nmap_raw_{sanitize_filename(target)}_{timestamp()}.txt"
        with open(raw_out, "w", encoding="utf-8") as f:
            f.write(f"## CMD: {cmd}\n\n")
            f.write(out or "")
            if err:
                f.write("\n\n## STDERR\n")
                f.write(err)
        cprint_ok(f"nmap raw output saved to {raw_out} (rc={rc})")
        time.sleep(RATE_LIMIT_SECONDS)
        parsed_summary = None
        if Path(xml_out).exists():
            try:
                parsed_summary = parse_nmap_xml(str(xml_out))
                parsed_fn = Path(outdir) / f"nmap_parsed_{sanitize_filename(target)}_{timestamp()}.txt"
                with open(parsed_fn, "w", encoding="utf-8") as f:
                    f.write(parsed_summary)
                cprint_ok(f"nmap parsed summary saved to {parsed_fn}")
            except Exception as e:
                cprint_warn(f"Failed to parse nmap XML: {e}")
        else:
            cprint_warn("Expected nmap XML file not found; parsing skipped.")
        return rc, str(raw_out), cmd, parsed_summary


    def parse_nmap_xml(xml_path: str) -> str:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        lines: list[str] = []
        # use .//host to be robust to possible namespaces or wrapper elements
        for host in root.findall(".//host"):
            # try to get address element with addr attribute
            addr = "unknown"
            for addr_el in host.findall("address"):
                if "addr" in addr_el.attrib:
                    addr = addr_el.get("addr")
                    break
            status_el = host.find("status")
            state = status_el.get("state") if status_el is not None else "unknown"
            lines.append(f"Host: {addr} ({state})")
            ports = host.find("ports")
            if ports is None:
                lines.append("  No ports element found.")
                continue
            for port in ports.findall("port"):
                pnum = port.get("portid")
                proto = port.get("protocol")
                st_el = port.find("state")
                st = st_el.get("state") if st_el is not None else "unknown"
                svc = port.find("service")
                svc_name = svc.get("name") if svc is not None and "name" in svc.attrib else ""
                svc_prod = svc.get("product") if svc is not None and "product" in svc.attrib else ""
                lines.append(f"  - {proto}/{pnum}: {st}  service={svc_name} product={svc_prod}")
        return "\n".join(lines)


    ### Helpers ###
    def is_valid_target(target: str) -> bool:
        if not target or target.strip() == "":
            return False
        t = target.strip()
        # domain-like or IP-like
        if any(ch.isalpha() for ch in t) and "." in t:
            return True
        try:
            socket.inet_pton(socket.AF_INET, t)
            return True
        except Exception:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, t)
            return True
        except Exception:
            pass
        return False


    ### GUI popup (Tkinter) ###
    def popup_collect(defaults: dict):
        if not TK_AVAILABLE:
            cprint_warn("Tkinter not available — falling back to CLI prompts.")
            return None

        collected = {}
        root = tk.Tk()
        root.title("HOOD — Quick Setup")
        root.geometry("600x600")
        root.resizable(False, False)

        frm = ttk.Frame(root, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        # Title
        lbl = ttk.Label(frm, text="HOOD-OSINT-TOOL     *Acid*", font=("Segoe UI", 20, "bold"))
        lbl.pack(pady=(0, 8))

        # Target
        ttk.Label(frm, text="Target (domain or IP):").pack(anchor=tk.W)
        target_var = tk.StringVar(value=defaults.get("target", ""))
        target_entry = ttk.Entry(frm, textvariable=target_var, width=60)
        target_entry.pack()

        # Mode: single / all
        mode_var = tk.StringVar(value=defaults.get("mode", "all"))
        ttk.Label(frm, text="Mode:").pack(anchor=tk.W, pady=(8, 0))
        mode_frame = ttk.Frame(frm)
        mode_frame.pack(anchor=tk.W)
        ttk.Radiobutton(mode_frame, text="Run all enabled tools automatically", variable=mode_var, value="all").pack(anchor=tk.W)
        ttk.Radiobutton(mode_frame, text="Run a single selected tool", variable=mode_var, value="single").pack(anchor=tk.W)

        # Tools checklist (for all mode) + dropdown (for single)
        tools = ["whois", "dns", "axfr", "brute", "nmap"]
        tool_vars = {t: tk.BooleanVar(value=(t in defaults.get("tools", tools))) for t in tools}
        tools_frame = ttk.LabelFrame(frm, text="Tools (check to enable)")
        tools_frame.pack(fill=tk.X, pady=(8, 0))
        for t in tools:
            ttk.Checkbutton(tools_frame, text=t.upper(), variable=tool_vars[t]).pack(side=tk.LEFT, padx=6, pady=4)

        # Single-tool dropdown
        ttk.Label(frm, text="If 'single' selected, choose tool:").pack(anchor=tk.W, pady=(8, 0))
        single_var = tk.StringVar(value=defaults.get("single", "dns"))
        single_choice = ttk.Combobox(frm, textvariable=single_var, values=tools, state="readonly", width=20)
        single_choice.pack(anchor=tk.W)

        # Confirmation checkbox (permission)
        confirm_var = tk.BooleanVar(value=defaults.get("confirm", False))
        chk = ttk.Checkbutton(
            frm,
            text="I confirm I have explicit permission to run active scans (nmap/AXFR/brute)",
            variable=confirm_var,
        )
        chk.pack(anchor=tk.W, pady=(12, 0))

        # nmap ports
        ttk.Label(frm, text="Nmap ports (optional, e.g. 1-65535 or 80,443):").pack(anchor=tk.W, pady=(8, 0))
        ports_var = tk.StringVar(value=defaults.get("ports", ""))
        ttk.Entry(frm, textvariable=ports_var, width=30).pack(anchor=tk.W)

        # Wordlist selection
        ttk.Label(frm, text="Subdomain wordlist (optional; leave blank to use built-in small list):").pack(anchor=tk.W, pady=(8, 0))
        wl_frame = ttk.Frame(frm)
        wl_frame.pack(fill=tk.X)
        wl_var = tk.StringVar(value=defaults.get("wordlist", ""))
        wl_entry = ttk.Entry(wl_frame, textvariable=wl_var, width=45)
        wl_entry.pack(side=tk.LEFT, padx=(0, 6))

        def browse_wl():
            p = filedialog.askopenfilename(title="Select wordlist", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            if p:
                wl_var.set(p)

        ttk.Button(wl_frame, text="Browse", command=browse_wl).pack(side=tk.LEFT)

        # Buttons
        btn_frame = ttk.Frame(frm)
        btn_frame.pack(fill=tk.X, pady=(12, 0))
        result = {}

        def on_ok():
            selected_tools = [t for t, v in tool_vars.items() if v.get()]
            result.update(
                {
                    "target": target_var.get().strip(),
                    "mode": mode_var.get(),
                    "tools": selected_tools,
                    "single": single_var.get(),
                    "confirm": confirm_var.get(),
                    "ports": ports_var.get().strip(),
                    "wordlist": wl_var.get().strip(),
                }
            )
            root.destroy()

        def on_cancel():
            result.clear()
            root.destroy()

        ttk.Button(btn_frame, text="Start", command=on_ok).pack(side=tk.RIGHT, padx=6)
        ttk.Button(btn_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT)
        root.mainloop()
        return result if result else None


    ### Main orchestration ###
    def run_all_chosen(opts: dict):
        target = opts["target"]
        outdir = opts["outdir"]
        tools = opts["tools"]
        confirm = opts["confirm"]
        ports = opts.get("ports") or None
        nmap_args = opts.get("nmap_args") or None
        wordlist_path = opts.get("wordlist") or None

        safe_makedirs(outdir)
        cprint_ok(f"Output directory: {outdir}")

        # WHOIS always passive
        if "whois" in tools:
            try:
                run_whois(target, outdir)
            except Exception as e:
                cprint_warn(f"whois failed: {e}")

        # DNS passive
        dns_fn = None
        if "dns" in tools:
            try:
                dns_fn, dns_records, ptrs = query_dns_records(target, outdir)
            except Exception as e:
                cprint_warn(f"dns step failed: {e}")

        # AXFR - active; require confirm
        if "axfr" in tools:
            if not confirm:
                cprint_warn("AXFR requested but permission not confirmed — skipping AXFR. (enable confirm to run)")
            else:
                try:
                    attempt_axfr(target, outdir)
                except Exception as e:
                    cprint_warn(f"AXFR failed: {e}")

        # brute - active (many queries), require confirm
        if "brute" in tools:
            if not confirm:
                cprint_warn("Subdomain brute-force requested but permission not confirmed — skipping brute.")
            else:
                wl = None
                if wordlist_path:
                    try:
                        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                            wl = [line.strip() for line in f if line.strip()]
                    except Exception as e:
                        cprint_warn(f"Failed to read wordlist {wordlist_path}: {e}; using built-in list.")
                        wl = None
                try:
                    brute_subdomains(target, outdir, wordlist=wl)
                except Exception as e:
                    cprint_warn(f"Brute-force failed: {e}")

        # nmap - active, require confirm; else dry-run plan
        if "nmap" in tools:
            do_scan = confirm
            try:
                run_nmap(target, outdir, ports=ports, extra_args=nmap_args, do_scan=do_scan)
            except Exception as e:
                cprint_warn(f"nmap step failed: {e}")


    def run_single_tool(opts: dict, tool: str):
        target = opts["target"]
        outdir = opts["outdir"]
        confirm = opts["confirm"]
        ports = opts.get("ports") or None
        nmap_args = opts.get("nmap_args") or None
        wordlist_path = opts.get("wordlist") or None

        safe_makedirs(outdir)
        if tool == "whois":
            run_whois(target, outdir)
        elif tool == "dns":
            query_dns_records(target, outdir)
        elif tool == "axfr":
            if not confirm:
                cprint_warn("AXFR requires confirm (permission). Skipping.")
            else:
                attempt_axfr(target, outdir)
        elif tool == "brute":
            if not confirm:
                cprint_warn("Brute-force requires confirm (permission). Skipping.")
            else:
                wl = None
                if wordlist_path:
                    try:
                        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                            wl = [line.strip() for line in f if line.strip()]
                    except Exception as e:
                        cprint_warn(f"Failed to read wordlist {wordlist_path}: {e}; using built-in list.")
                        wl = None
                brute_subdomains(target, outdir, wordlist=wl)
        elif tool == "nmap":
            do_scan = confirm
            run_nmap(target, outdir, ports=ports, extra_args=nmap_args, do_scan=do_scan)
        else:
            cprint_warn(f"Unknown tool: {tool}")


    def run():
        parser = argparse.ArgumentParser(description="OSINT helper — whois,dns,axfr,brute,nmap (with GUI popup)")
        parser.add_argument("--target", "-t", help="Target domain or IP (e.g. example.com or 93.184.216.34)")
        parser.add_argument("--outdir", "-o", default=f"osint_{timestamp()}", help="Output directory")
        parser.add_argument("--mode", choices=["all", "single"], default="all", help="Run all enabled tools or a single selected tool")
        parser.add_argument("--tools", help="Comma-separated tools to enable (whois,dns,axfr,brute,nmap). Default: all")
        parser.add_argument("--single-tool", help="If mode==single, which tool to run (whois,dns,axfr,brute,nmap)")
        parser.add_argument("--wordlist", help="Path to subdomain wordlist file (optional)")
        parser.add_argument("--ports", help="Ports for nmap (e.g. 1-65535 or 80,443)")
        parser.add_argument("--nmap-args", help="Custom nmap args (overrides default)")
        parser.add_argument("--confirm", action="store_true", help="You confirm you have permission to run active network checks (AXFR/nmap/brute)")
        parser.add_argument("--no-gui", action="store_true", help="Do not show GUI popup even if available (use CLI args only)")
        args = parser.parse_args()

        print_logo()

        # collect defaults for popup
        defaults = {
            "target": args.target or "",
            "mode": args.mode,
            "tools": (args.tools.split(",") if args.tools else ["whois", "dns", "axfr", "brute", "nmap"]),
            "single": args.single_tool or "dns",
            "confirm": args.confirm,
            "ports": args.ports or "",
            "wordlist": args.wordlist or "",
            "nmap_args": args.nmap_args or None,
        }

        gui_opts = None
        if TK_AVAILABLE and not args.no_gui:
            try:
                gui_opts = popup_collect(defaults)
            except Exception as e:
                cprint_warn(f"GUI popup failed: {e}; falling back to CLI prompts.")
                gui_opts = None

        if gui_opts:
            # merge GUI options with CLI flags (GUI overrides)
            target = gui_opts.get("target")
            mode = gui_opts.get("mode")
            tools = gui_opts.get("tools")
            single = gui_opts.get("single")
            confirm = gui_opts.get("confirm")
            ports = gui_opts.get("ports") or args.ports
            wordlist = gui_opts.get("wordlist") or args.wordlist
            nmap_args = gui_opts.get("nmap_args") or args.nmap_args
        else:
            # use CLI args / defaults
            target = args.target
            mode = args.mode
            tools = (args.tools.split(",") if args.tools else ["whois", "dns", "axfr", "brute", "nmap"])
            single = args.single_tool or "dns"
            confirm = args.confirm
            ports = args.ports
            wordlist = args.wordlist
            nmap_args = args.nmap_args or None

        if not target:
            # prompt on CLI if none
            try:
                target = input("Target (domain or IP): ").strip()
            except Exception:
                cprint_err("No target provided and cannot prompt.")
                sys.exit(2)

        if not is_valid_target(target):
            cprint_err(f"Invalid target: {target}")
            sys.exit(2)

        opts = {
            "target": target,
            "outdir": args.outdir,
            "tools": tools,
            "single": single,
            "confirm": confirm,
            "ports": ports,
            "wordlist": wordlist,
            "nmap_args": nmap_args,
            "mode": mode,
        }

        # Mode dispatch
        if mode == "all":
            run_all_chosen(opts)
        else:
            # single
            run_single_tool(opts, opts["single"])

        print("\n" + Fore.CYAN + Style.BRIGHT + "=== Done ===" + Style.RESET_ALL)
        print(Fore.CYAN + f"Full results saved to: {opts['outdir']}")


    if __name__ == "__main__":
        run()

def hprint(s):
    for c in s + "\n":
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(8.0 / 100)

def ploit():
    hprint(f"""{Fore.YELLOW}
[+]Acid> From this point forward a shellcode will be created automatically and will
    be saved in the current directory of the tool a listener will also be set.
    you will have to set the LHOST and ports yo exploit and listen to
    Read the instruction below carefully{Style.RESET_ALL}""")
    print(f"""{Fore.MAGENTA}
1.After the listener has been set open a new terminal
2.Navigate to the directory in which you have saved the hood files{Style.RESET_ALL}
{Fore.GREEN}3. Run: python eternal_checker.py <ipadress of the machine you are attacking>{Style.RESET_ALL}
{Fore.CYAN}4.After this there are three eternalblue_eploits to choose from:
    1.'eternalblue_exploit7.py' for windows 7.
    2.'eternalblue_exploit8.py' for windows 8.
    3.'eternalblue_exploits10.py' for windows 10.{Style.RESET_ALL} 
{Fore.GREEN}5.Run:python eternalblue_exploit7.py <TARGET-IP> <PATH/TO/SHELLCODE/sc_all.bin> <Number of Groom Connections (optional)>       
                """)
    hprint(f"[+]Acid > this is where hood terminal exits.Happy exploit :) ")
    hprint(f"{Fore.RED}Starting shellcode generator.......")
    gen_shellcode()
    hprint(f"{Fore.RED}starting listener......")
    gen_listener()

LOGO2 = r"""
╔══════════════════════════════════════════════════════╗
║  ░█▄█░█▀█░█▀█░█▀▄  TERMINAL  >By Duncan Kinyua(Acid) ║
║  ░█▀█░█▄█░█▄█░█▄▀       *Exploit like a pro!!        ║
╚══════════════════════════════════════════════════════╝
"""
LOGO = r"""
╔══════════════════════════════════════════════════════╗
║  ░█▄█░█▀█░█▀█░█▀▄  ATTACKER  >By Duncan Kinyua(Acid) ║
║  ░█▀█░█▄█░█▄█░█▄▀       *Exploit like a pro!!        ║
╚══════════════════════════════════════════════════════╝
"""
welcm = f"""{Fore.YELLOW}
 [+]Acid> 'Hello user before you start using Hood attacker make sure you,
    are well aware of what you are doing!.
    LEARN:metasploit,nmap and ofcourse Python if you want to understand
    how this tool works.Don't operate like a script kittie!.
    This tool also uses linux terminal commands search as 'cd,ls and cd..'
    READ INSTRUCTIONS FIRST!  HAPPY HACKING
    And remember 'hackers don't breakin they login.' {Style.RESET_ALL} """

print(Fore.CYAN + Style.BRIGHT + LOGO + Style.RESET_ALL)
hprint(Fore.YELLOW + "[+]Acid> 'Welcome To HOOD Attacker! The Altimate Hacker Exploit tool' " + Style.RESET_ALL)
print(Fore.RED + " *tip* Run HOOD in root terminal" + Style.RESET_ALL)
hprint(welcm)
print(f"""
                    {Fore.RED}INSTRUCTIONS!{Style.RESET_ALL}
    {Fore.BLUE}TO EXPLORE TERMINAL:
    -Start by running the command 'ls' on the terminal to view available options
    -USE 'cd' to open Directories .Example 'cd Exploits'.
    -USE './' to open tools in the Directories .Example './Watchdog'.
    -USE the command 'exit' to exit terminal or 'cd ..' to go back to main terminal.{Style.RESET_ALL}""")
hprint(f"{Fore.YELLOW}[+]Acid> 'Eaasssy!!!...Lets go!!!' ")
user = input(f"{Fore.GREEN}[+]Enter username: {Style.RESET_ALL}")

print(f"{Fore.GREEN}Welcome to HOOD Terminal {user}{Style.RESET_ALL}")

def main():
    Attacks = f"""{Fore.BLUE}
Exploits(Choose rensponsibly)
Osint
Scanners
Interpreters"""
    opt = input(f"""{Fore.RED}
|-[{Fore.GREEN}Hood{Fore.YELLOW}@{Fore.CYAN}{user}{Fore.RED}] 
|----{Fore.YELLOW}${Style.RESET_ALL} """)
    if opt == "ls":
        os.system('clear')
        print(Fore.BLUE + LOGO2 + Style.RESET_ALL)
        print(Attacks)
        ansa = input(
            f"""{Fore.RED}
    
|-[{Fore.GREEN}Hood{Fore.YELLOW}@{Fore.CYAN}{user}{Fore.RED}] 
|----{Fore.YELLOW}${Style.RESET_ALL} """
        )
        if ansa == "cd Exploits":
            os.system('clear')
            print(
                f"""{Fore.BLUE}
:)
Phonesploit
Smile
""")
            ans = input(
                f"""{Fore.RED}
|-[{Fore.GREEN}Hood{Fore.YELLOW}@{Fore.CYAN}{user}{Fore.RED}]-[{Style.RESET_ALL}~/Exploits{Fore.RED}] 
|----{Fore.YELLOW}${Style.RESET_ALL} """
            )
            if ans == "./:)":
                ploit()
            elif ans == "./Phonesploit":
                os.system('python3 phonesploitpro.py')
            elif ans == "./Smile":
                os.system('./saycheese.sh')
                main()
            elif ans == "cd ..":
                os.system('clear')
                print(Fore.BLUE + LOGO2 + Style.RESET_ALL)
                main()
            elif ans == "exit":
                hprint(f"{Fore.GREEN}[+]Exiting HOOD Terminal")
                sys.exit()
            else:
                print(f"{Fore.RED}Invalid Option!{Style.RESET_ALL}")
                print(Fore.RED + LOGO2 + Style.RESET_ALL)
                main()
        elif ansa == "cd Osint":
            print(
                f"""{Fore.BLUE}
Mass-scanner
Iplocator
Mail-verifier
        """
            )
            ans = input(
                f"""{Fore.RED}
|-[{Fore.GREEN}Hood{Fore.YELLOW}@{Fore.CYAN}{user}{Fore.RED}]-[{Style.RESET_ALL}~/Osint{Fore.RED}] 
|----{Fore.YELLOW}${Style.RESET_ALL} """
            )
            if ans == "./Mass-scanner":
                osint()
                main()
            elif ans == "./Iplocator":
                iplocate()
                main()
            elif ans == "./Mail-verifier":
                os.system('python3 knockmail.py')
                main()
            elif ans == "cd ..":
                os.system('clear')
                print(Fore.BLUE + LOGO2 + Style.RESET_ALL)
                main()
            elif ans == "exit":
                hprint(f"{Fore.GREEN}[+]Exiting HOOD Terminal")
                sys.exit()
            else:
                print(f"{Fore.RED}Invalid Option!{Style.RESET_ALL}")
                print(Fore.BLUE + LOGO2 + Style.RESET_ALL)
                main()
        elif ansa == "cd Scanners":
            print(
                f"""{Fore.BLUE}
Netdicover
Watchdog
        """
            )
            ans = input(
                f"""{Fore.RED}
|-[{Fore.GREEN}Hood{Fore.YELLOW}@{Fore.CYAN}{user}{Fore.RED}]-[{Style.RESET_ALL}~/Scanners{Fore.RED}] 
|----{Fore.YELLOW}${Style.RESET_ALL} """
            )
            if ans == "./Netdiscover":
                net()
                main()
            elif ans == "./Watchdog":
                watch()
                main()
            elif ans == "cd ..":
                os.system('clear')
                print(Fore.YELLOW + LOGO2 + Style.RESET_ALL)
                main()
            elif ans == "exit":
                hprint(f"{Fore.GREEN}[+]Exiting HOOD Terminal")
                sys.exit()
            else:
                print(f"{Fore.RED}Invalid Option!{Style.RESET_ALL}")
                print(Fore.RED + LOGO2 + Style.RESET_ALL)
                main()
        elif ansa == "cd Interpreters":
            print(
                f"""{Fore.BLUE}
Binary
Ceaser
        """
            )
            ans = input(
                f"""{Fore.RED}
|-[{Fore.GREEN}Hood{Fore.YELLOW}@{Fore.CYAN}{user}{Fore.RED}]-[{Style.RESET_ALL}~/Scanners{Fore.RED}] 
|----{Fore.YELLOW}${Style.RESET_ALL} """
            )
            if ans == "./Binary":
                binary()
                main()
            elif ans == "./Ceaser":
                ceaser()
                main()
            elif ans == "cd ..":
                os.system('clear')
                print(Fore.YELLOW + LOGO2 + Style.RESET_ALL)
                main()
            elif ans == "exit":
                hprint(f"{Fore.GREEN}[+]Exiting HOOD Terminal")
                sys.exit()
            else:
                print(f"{Fore.RED}Invalid Option!{Style.RESET_ALL}")
                print(Fore.RED + LOGO2 + Style.RESET_ALL)
                main()
        elif ansa == "exit":
            hprint(f"{Fore.GREEN}[+]Exiting HOOD Terminal")
            sys.exit()
        else:
            print(f"{Fore.RED}Invalid Option!{Style.RESET_ALL}")
            print(Fore.RED + LOGO2 + Style.RESET_ALL)
            main()
    elif opt == "cd Exploits":
        print(
                f"""{Fore.BLUE}
:)
Phonesploit
Smile
""")
        trm = input(
                f"""{Fore.RED}
|-[{Fore.GREEN}Hood{Fore.YELLOW}@{Fore.CYAN}{user}{Fore.RED}]-[{Style.RESET_ALL}~/Exploits{Fore.RED}] 
|----{Fore.YELLOW}${Style.RESET_ALL} """)
        if trm == "./:)":
            ploit()
        elif trm == "./Phonesploit":
            os.system('python3 phonesploitpro.py')
        elif trm == "./Smile":
            os.system('./saycheese.sh')
            main()
        elif trm == "cd ..":
            os.system('clear')
            print(Fore.CYAN + LOGO2 + Style.RESET_ALL)
            main()
        elif trm == "exit":
            hprint(f"{Fore.GREEN}[+]Exiting HOOD Terminal")
            sys.exit()
        else:
            print(f"{Fore.RED}Invalid Option!{Style.RESET_ALL}")
            print(Fore.YELLOW + LOGO2 + Style.RESET_ALL)
            main()

    elif opt == "cd Osint":
        print(
                f"""{Fore.BLUE}
Mass-scanner
Iplocator
Mail-verifier
        """)
        trm = input(
                f"""{Fore.RED}
|-[{Fore.GREEN}Hood{Fore.YELLOW}@{Fore.CYAN}{user}{Fore.RED}]-[{Style.RESET_ALL}~/Osint{Fore.RED}] 
|----{Fore.YELLOW}${Style.RESET_ALL} """)
        if trm == "./Mass-scanner":
            osint()
            main()
        elif trm == "./Iplocator":
            iplocate()
            main()
        elif trm == "./Mail-verifier":
            os.system('python3 knockmail.py')
            main()
        elif trm == "cd ..":
            os.system('clear')
            print(Fore.BLUE + LOGO2 + Style.RESET_ALL)
            main()
        elif trm == "exit":
            hprint(f"{Fore.GREEN}[+]Exiting HOOD Terminal")
            sys.exit()
        else:
            print(f"{Fore.RED}Invalid Option!{Style.RESET_ALL}")
            print(Fore.BLUE + LOGO2 + Style.RESET_ALL)
            main()
    elif opt == "cd Scanners":
        print(
                f"""{Fore.BLUE}
Netdicover
Watchdog
        """)
        trm = input(
                f"""{Fore.RED}
|-[{Fore.GREEN}Hood{Fore.YELLOW}@{Fore.CYAN}{user}{Fore.RED}]-[{Style.RESET_ALL}~/Scanners{Fore.RED}] 
|----{Fore.YELLOW}${Style.RESET_ALL} """)
        if trm == "./Netdiscover":
            net()
            main()
        elif trm == "./Watchdog":
            watch()
            main()
        elif trm == "cd ..":
            os.system('clear')
            print(Fore.CYAN + LOGO2 + Style.RESET_ALL)
            main()
        elif trm == "exit":
            hprint(f"{Fore.GREEN}[+]Exiting HOOD Terminal")
            sys.exit()
        else:
            print(f"{Fore.RED}Invalid Option!{Style.RESET_ALL}")
            print(Fore.MAGENTA + LOGO2 + Style.RESET_ALL)
            main()
    elif opt == "cd Interpreters":
        print(
                f"""{Fore.BLUE}
Binary
Ceaser
        """)
        trm = input(
                f"""{Fore.RED}
|-[{Fore.GREEN}Hood{Fore.YELLOW}@{Fore.CYAN}{user}{Fore.RED}]-[{Style.RESET_ALL}~/Scanners{Fore.RED}] 
|----{Fore.YELLOW}${Style.RESET_ALL} """)
        if trm == "./Binary":
            binary()
            main()
        elif trm == "./Ceaser":
            ceaser()
            main()
        elif trm == "cd ..":
            os.system('clear')
            print(Fore.CYAN + LOGO2 + Style.RESET_ALL)
            main()
        elif trm == "exit":
            hprint(f"{Fore.GREEN}[+]Exiting HOOD Terminal")
            sys.exit()
        else:
            print(f"{Fore.RED}Invalid Option!{Style.RESET_ALL}")
            print(Fore.CYAN + LOGO2 + Style.RESET_ALL)
            main()
    
    elif opt == "clear":
        os.system('clear')
        print(Fore.CYAN + LOGO2 + Style.RESET_ALL)
        main()
        
    elif opt == "exit":
        print(f"{Fore.GREEN}[+]Exiting HOOD Terminal")
        sys.exit()
    else:
        print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
        print(Fore.YELLOW + LOGO2 + Style.RESET_ALL)
        main()
if __name__ == "__main__":
    main()
