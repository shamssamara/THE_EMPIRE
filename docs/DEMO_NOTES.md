# THE_EMPIRE — Demonstration Evidence

The screenshots in this directory were supplied by the project author and show a local laboratory run. They are evidence of the displayed operations, **not** an independent security audit.

| File | Shown operation | Evidence and limits |
| --- | --- | --- |
| `01-kali-tls-session.png` | Kali connects to Windows lab endpoint | TLS 1.3 connection reported, COMMAND mode, session 1. Does not establish certificate verification or identity authentication. |
| `02-windows-tls-listener.png` | Windows PowerShell server | Accepts a connection and reports generating a certificate using `cryptography`. |
| `03-remote-files-and-sha256.png` | Remote directory listing and file download | `ls` maps to a Windows listing; a 15-byte lab file is downloaded and a SHA-256 hash is displayed. |
| `04-windows-share-enumeration.png` | Windows share listing | Shows share names provided by Windows. Does not establish any permissions to access shares. |

## Reproducibility

- Platforms seen: Kali Linux client and Windows server.
- Example lab endpoint: `192.168.1.200:4444` (private RFC1918 address).
- The exact code revision and full runtime environment are not documented in the screenshots alone.
- For a safely repeatable network connectivity demo, use the loopback Echo example in the repository README rather than exposing remote command services.

## Before public sharing

The screenshots show local paths, an internal IP address, and sample file names. Review these details before making a repository public. Avoid sharing credentials, tokens, VPN information, or logs from real systems.
