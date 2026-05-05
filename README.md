# passdiger

Active Directory credential exposure auditor. Scans LDAP object attributes for
inadvertently stored passwords, secrets, tokens, API keys, and connection strings.

## How it works

1. **Schema discovery** — built-in attributes are distinguished from custom
   schema extensions via `attributeSchema.systemFlags`.
2. **Pattern detection** — password key=value, SQL connection strings, URLs
   with embedded credentials, AWS / GitHub / Slack / Stripe / Google / Azure
   tokens, JWTs, PEM private keys, and bcrypt / shadow / NTLM hashes.
3. **Encoded-secret decoding** — base64 and hex blobs are decoded and re-scanned.
4. **Context heuristic** — credential keywords followed by high-entropy tokens.

False positives such as GUIDs, SIDs, ISO dates, phone numbers, version strings,
and placeholder values are suppressed.

## Install

With `pipx` (recommended — installs in an isolated env and exposes a `passdiger` command):

```
pipx install .
```

From a Git repository:

```
pipx install git+https://github.com/<NeCr00>/passdiger.git
```

Or in the current environment:

```
pip install .
```

Requires Python 3.8+ and `ldap3>=2.9`.

## Usage

Anonymous bind:

```
python3 passdiger.py -d corp.local -s 10.0.0.5
```

Authenticated bind over LDAPS:

```
python3 passdiger.py -d corp.local -s dc1.corp.local \
    -u 'CORP\auditor' -p 'P@ssw0rd' --use-ssl
```

Full audit with custom-attribute dump, written as JSON:

```
python3 passdiger.py -d corp.local -s 10.0.0.5 \
    -u auditor@corp.local -p '...' \
    --show-all-custom -o json -O report.json
```

## Options

### Connection

| Flag                   | Description                                     |
| ---------------------- | ----------------------------------------------- |
| `-d, --domain`         | Domain FQDN. Required.                          |
| `-s, --dc, --server`   | Domain controller hostname or IP. Required.    |
| `-u, --user`           | Bind username (UPN, DN, or `DOMAIN\sam`).      |
| `-p, --password`       | Bind password.                                  |
| `--auth`               | `auto` \| `simple` \| `ntlm` \| `anonymous`.   |
| `--port`               | LDAP/LDAPS port override.                       |
| `--use-ssl`            | Use LDAPS (TLS).                                |
| `--no-verify-cert`     | Skip TLS certificate validation.                |
| `--timeout`            | Network timeout in seconds.                     |

### Scope

| Flag             | Description                                |
| ---------------- | ------------------------------------------ |
| `-b, --base-dn`  | Base DN. Defaults to rootDSE.              |
| `--filter`       | LDAP object filter.                        |
| `--page-size`    | Paged search size.                         |
| `--max-objects`  | Stop after N objects.                      |

### Detection

| Flag                 | Description                                          |
| -------------------- | ---------------------------------------------------- |
| `--min-confidence`   | Minimum reported confidence, 0-100. Default 55.     |
| `--only-common`      | Inspect only well-known credential-prone attributes. |
| `--show-all-custom`  | Print every custom attribute, even with no findings. |
| `--mask-values`      | Mask matched values in output.                       |

### Output

| Flag                  | Description                          |
| --------------------- | ------------------------------------ |
| `-o, --output-format` | `table` \| `json` \| `csv`.         |
| `-O, --output-file`   | Write to file instead of stdout.     |
| `-q, --quiet`         | Suppress progress output.            |


## Severity and exit codes

| Severity   | Exit code |
| ---------- | --------- |
| `CRITICAL` | 30        |
| `HIGH`     | 20        |
| `MEDIUM`   | 10        |
| Clean      | 0         |

Connection or runtime errors return non-zero codes in the 1–5 range.
