"""Rules for POSIX shell, AppleScript and unit-file content: the Linux/macOS counterpart of SCRIPT_RULES."""
from __future__ import annotations

from .textrules import Rule, _r

SHELL_RULES: list[Rule] = [
    _r("SH-PIPE-EXEC", "download-exec", "medium", "Download piped into a shell",
       r"\b(?:curl|wget|fetch)\b[^\n|;]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
       r"|\b(?:ba|z)?sh\s+-c\s+[\"']?\$\((?:curl|wget)\b"
       r"|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b",
       "Remote content is fetched and executed without being saved or checked."),
    _r("SH-REVSHELL", "c2", "high", "Reverse shell",
       r"/dev/(?:tcp|udp)/[^\s/]+/\d+"
       r"|\bnc(?:at)?\b[^\n]{0,80}\s-(?:e|c)\s+\S*(?:sh|bash)\b"
       r"|\bmkfifo\b[^\n]{0,120}\|\s*(?:/bin/)?(?:ba)?sh\b[^\n]{0,80}\bnc\b"
       r"|\bsocat\b[^\n]{0,120}\bexec:[^\n]{0,40}(?:sh|bash)"
       r"|python[23]?\s+-c\s+[^\n]{0,200}socket[^\n]{0,200}(?:dup2|pty\.spawn)"
       r"|\bperl\s+-e\s+[^\n]{0,200}socket[^\n]{0,200}exec",
       "Connects a shell to a remote host."),
    _r("SH-DECODE-EXEC", "obfuscation", "medium", "Decoded payload piped into an interpreter",
       r"\bbase64\s+(?:-d|--decode|-D)\b[^\n|]{0,80}\|\s*(?:sudo\s+)?(?:(?:ba|z|da)?sh|python[23]?|perl)\b"
       r"|\becho\s+[A-Za-z0-9+/=]{60,}\s*\|\s*base64\s+(?:-d|--decode|-D)"
       r"|\bxxd\s+-r\b[^\n|]{0,80}\|\s*(?:ba)?sh\b|\beval\s+[\"']?\$\(\s*(?:echo|printf)\s+[^\n]{0,400}\|\s*base64",
       "Script hides its real commands in an encoded blob."),
    _r("SH-PRELOAD", "persistence", "high", "Library preload hijack",
       r"/etc/ld\.so\.preload|\bLD_PRELOAD\s*=\s*/(?:tmp|var/tmp|dev/shm|home)[^\s]*\.so|\bDYLD_INSERT_LIBRARIES\s*=",
       "Forces a library into every process, a classic userland rootkit technique."),
    _r("SH-PERSIST", "persistence", "low", "Persistence command",
       r"\bcrontab\s+-\b|\(\s*crontab\s+-l[^\n]{0,80}\)\s*\|\s*crontab|>>?\s*/etc/cron\.|>>?\s*/var/spool/cron"
       r"|\bsystemctl\s+(?:--user\s+)?enable\b|>>?\s*~?/?[^\s]*\.(?:bashrc|zshrc|profile|bash_profile)\b"
       r"|\blaunchctl\s+(?:load|bootstrap|enable)\b|>>?\s*[^\s]*/Library/Launch(?:Agents|Daemons)/"
       r"|>>?\s*[^\s]*/\.ssh/authorized_keys\b|>>?\s*/etc/rc\.local\b",
       "Installs something that runs again at login, boot or on a schedule."),
    _r("SH-EVASION", "defense-evasion", "medium", "Log or history tampering",
       r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|HISTFILE\s*=\s*/dev/null|HISTSIZE\s*=\s*0\b"
       r"|\b(?:rm|shred|truncate)\b[^\n]{0,60}(?:\.bash_history|/var/log/(?:auth|secure|syslog|wtmp|btmp|lastlog))"
       r"|>\s*/var/log/(?:auth\.log|secure|wtmp|btmp|lastlog)\b|\bchattr\s+\+i\b"
       r"|\bsetenforce\s+0\b|\bspctl\s+--master-disable\b|\bcsrutil\s+disable\b"
       r"|\bxattr\s+-(?:d|r?d|cr?)\s+[^\n]{0,40}com\.apple\.quarantine|\bufw\s+disable\b|\biptables\s+-F\b",
       "Removes traces or switches off a protection."),
    _r("SH-CREDS", "credential-access", "high", "Credential harvesting",
       r"\bcat\b[^\n]{0,40}/etc/shadow\b|\b(?:tar|zip|cp|curl|scp)\b[^\n]{0,120}(?:\.ssh/id_|\.aws/credentials|\.gnupg/|"
       r"\.kube/config|login\.keychain|Login Data|cookies\.sqlite|\.mozilla/firefox)"
       r"|\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain)\b[^\n]{0,80}-[gdw]\b"
       r"|osascript[^\n]{0,200}display dialog[^\n]{0,200}(?:password|hidden answer)",
       "Reads or copies stored credentials."),
    _r("SH-MINER", "impact", "medium", "Cryptominer indicators",
       r"\bxmrig\b|stratum\+(?:tcp|ssl)://|\bminerd\b|--donate-level\b|\bcpuminer\b",
       "Strings typical of a cryptocurrency miner."),
    _r("SH-SUID", "privilege-escalation", "medium", "Sets the setuid bit or edits sudoers",
       r"\bchmod\s+(?:[ugoa]*\+s|[2467][0-7]{3})\s+\S+|>>?\s*/etc/sudoers(?:\.d/\S+)?\b[^\n]{0,0}|NOPASSWD:\s*ALL[^\n]{0,40}>>?\s*/etc/sudoers",
       "Creates a way to run code as root later."),
    _r("SH-HIDDEN-EXEC", "stealth", "low", "Runs a hidden file from a temporary directory",
       r"(?:^|[\s;&|\"'])(?:/tmp|/var/tmp|/dev/shm|/private/tmp)/\.[A-Za-z0-9_.\-]+(?:\s|$|;|&)",
       "Dot-files in world-writable directories are a common place to stage payloads."),
    _r("SH-OSASCRIPT", "execution", "medium", "AppleScript shell execution with administrator rights",
       r"osascript[^\n]{0,300}do shell script[^\n]{0,300}with administrator privileges",
       "Asks the user for their password and then runs a command as root."),
]
