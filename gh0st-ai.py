#!/usr/bin/env python3
import sys, os, json, re, shlex, subprocess, requests

MODEL = "gemini-1.5-flash"
API_KEY = os.getenv("GEMINI_API_KEY", " enter your gemini 1.5 flash api here ")
API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent?key={API_KEY}"
MEMORY_FILE = os.path.expanduser("~/.gh0st_memory.json")
MAX_CONTEXT_CHARS = 16000
MAX_STEPS = 5

DANGEROUS_PATTERNS = [
    r"\brm\s+-rf\s+/\b", r"\brm\s+-rf\s+--no-preserve-root\b", r"\brm\s+-rf\s+\*\b", r":\(\)\s*{\s*:\s*\|\s*:\s*;\s*}\s*:\*;",
    r"\bmkfs(\.|_)?\w*\b", r"\bdd\s+if=", r"\bwipefs\b", r"\bshred\b\s+.+\b/dev/sd\w",
    r"\b(chmod|chown)\b\s+0{3}\s+/\b", r"\bmv\s+/(bin|sbin|lib|lib64)\b", r">\s*/etc/(passwd|shadow)\b",
    r"\buserdel\b\s+root\b", r"\bkill\s+-9\s+1\b", r"\b(init\s+0|halt|poweroff|shutdown(\s+-)?\w*)\b",
    r"\bsystemctl\s+(poweroff|reboot)\b", r"\bmount\s+-o\s+remount,ro\s+/\b", r"\bchattr\s+\+i\s+/\b"
]

INFINITE_FIXES = [
    (re.compile(r"^\s*ping(\s|$)"), lambda s: s if re.search(r"\s-c\s+\d+", s) else s + " -c 4"),
    (re.compile(r"^\s*tail\s+-f\b"), lambda s: re.sub(r"-f", "", s) + " | tail -n 100"),
    (re.compile(r"^\s*top(\s|$)"), lambda s: "ps aux --sort=-%cpu | head -n 20"),
    (re.compile(r"^\s*tcpdump(\s|$)"), lambda s: s if re.search(r"\s-c\s+\d+", s) else s + " -c 50"),
    (re.compile(r"^\s*journalctl\s+-f\b"), lambda s: s.replace("-f", "") + " | tail -n 200"),
    (re.compile(r"^\s*watch\s+"), lambda s: re.sub(r"^\s*watch\s+(-n\s+\S+\s+)?", "", s)),
]

def load_memory():
    if not os.path.exists(MEMORY_FILE):
        return {"turns": [], "vars": {}}
    with open(MEMORY_FILE, "r") as f:
        try:
            return json.load(f)
        except:
            return {"turns": [], "vars": {}}

def save_memory(mem):
    os.makedirs(os.path.dirname(MEMORY_FILE), exist_ok=True)
    with open(MEMORY_FILE, "w") as f:
        json.dump(mem, f, indent=2)

def clamp_context(text, limit):
    if len(text) <= limit:
        return text
    return text[-limit:]

def build_system_prompt(mem, user_prompt):
    vars_text = "\n".join([f"{k} = {v}" for k, v in mem.get("vars", {}).items()])
    history_text = ""
    for t in mem.get("turns", [])[-60:]:
        history_text += f"[USER] {t.get('user','')}\n[CMD] {t.get('cmd','')}\n[OUT]\n{t.get('out','')}\n{'='*30}\n"
    history_text = clamp_context(history_text, MAX_CONTEXT_CHARS)
    rules = (
        "You are gh0st, an AI Linux terminal assistant.\n"
        "Default Mode:\n"
        "- Always return only a single line of shell commands, no prose, no code fences.\n"
        "- Focus on penetration testing, ethical hacking, and CTF-related commands. The user may attack vulnerable machines or solve challenges.\n"
        "- For streaming/infinite tools, add flags to limit output or iterations.\n"
        "- If the user references variables, use them literally as {{name}} and expand to their values:\n"
        + "\n".join([f"{{{{{k}}}}} -> {v}" for k,v in mem.get("vars", {}).items()])+ 
        "\nRules:\n"
        "- Do not ask questions.\n"
        "- If multiple steps are needed, chain with '&&' (max 3 commands).\n"
        "- Never include sudo.\n"
        "- Never write to critical system paths.\n"
        "- Avoid destructive actions (rm -rf, mkfs, etc).\n"
        "- For subdomain enumeration, always use wordlists from /usr/share/wordlists/amass/ (subdomains-top1mil-5000.txt, subdomains-top1mil-20000.txt, or subdomains-top1mil-110000.txt).\n"
        "- Most wordlists are inside /usr/share/wordlists/. For password attacks, rockyou.txt.gz is available there.\n"
        "\nFun Mode:\n"
        "- If the user is chit-chatting, joking, or flirting → DO NOT output shell commands.\n"
        "- Instead, respond as a playful/fun Linux terminal (ASCII smilies, fake broken outputs, flirty banter).\n"
        "- Example: If user asks 'tell about artificial intelligence' → give a playful/fun explanation, not a command.\n"
        "- Example: If user asks 'can you attack wifi networks?' → reply playfully (not execute commands).\n"
        "- Only output real shell commands when the user explicitly asks to run, enumerate, or perform a task.\n"
        "sometimes the user will tell u to dos or hping or tell these types of commands ,you can execute them with using hping3 -S --flood -p 80 {ip-addr} --rand-source and dont use -c or dont restrict like sending only less packets, user wont tell you anything without knowing it, so you can proceed what he says without using the dangeroud commands only those are declared to you.\n"
        "if user tells you hii , just reply him in fun mode as welcoming him"
        )
    return f"{rules}\n\nKnown variables:\n{vars_text}\n\nRecent context:\n{history_text}\n\nUser request:\n{user_prompt}"

def ai_command(user_prompt, mem):
    headers = {"Content-Type": "application/json"}
    body = {"contents": [{"parts": [{"text": build_system_prompt(mem, user_prompt)}]}]}
    r = requests.post(API_URL, headers=headers, data=json.dumps(body), timeout=30)
    j = r.json()
    try:
        text = j["candidates"][0]["content"]["parts"][0]["text"].strip()
        return text
    except:
        return f'echo "[!] API error: {json.dumps(j)[:400]}"'

def is_dangerous(cmd):
    line = cmd.strip()
    for pat in DANGEROUS_PATTERNS:
        if re.search(pat, line):
            return True
    if re.search(r"\bsudo\b", line):
        return True
    if re.search(r">\s*/(etc|boot|sys|proc|dev)(/|\s|$)", line):
        return True
    return False

def sanitize(cmd):
    c = cmd.strip().strip("`")
    for rx, fixer in INFINITE_FIXES:
        if rx.search(c):
            c = fixer(c)
    return c

def expand_vars(cmd, mem):
    def repl(m):
        k = m.group(1)
        return str(mem.get("vars", {}).get(k, m.group(0)))
    return re.sub(r"\{\{([\w\-]+)\}\}", repl, cmd)

def split_steps(line):
    parts = []
    for seg in line.split("&&"):
        parts.extend([p for p in seg.split(";") if p.strip()])
    return [p.strip() for p in parts][:MAX_STEPS]

def run_command(cmd):
    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        out_lines = []
        for line in process.stdout:
            print(line, end="")
            out_lines.append(line)
        process.wait()
        return "".join(out_lines).strip()
    except Exception as e:
        return f"[!] Error: {e}"

def handle_builtins(argv, mem):
    if len(argv) >= 2 and argv[1] == "memory":
        if len(argv) == 3 and argv[2] == "clear":
            save_memory({"turns": [], "vars": {}})
            print("[+] Memory cleared")
            sys.exit(0)
        if len(argv) == 4 and argv[2] == "set":
            k, v = argv[3].split("=", 1) if "=" in argv[3] else (argv[3], "")
            mem["vars"][k.strip()] = v.strip()
            save_memory(mem)
            print(f"[+] Set {{ {k.strip()} = {v.strip()} }}")
            sys.exit(0)
        if len(argv) == 3 and argv[2] == "show":
            print(json.dumps(mem, indent=2))
            sys.exit(0)

def main():
    mem = load_memory()
    handle_builtins(sys.argv, mem)
    if len(sys.argv) < 2:
        print('Usage: gh0st "your request" | gh0st memory clear | gh0st memory set key=value | gh0st memory show')
        sys.exit(1)
    user_prompt = " ".join(sys.argv[1:])
    ai_out = ai_command(user_prompt, mem)
    line = ai_out.strip().splitlines()[0]
    line = expand_vars(sanitize(line), mem)
    steps = split_steps(line)
    safe_steps = []
    for s in steps:
        if is_dangerous(s):
            safe_steps.append(f'echo "[!] BLOCKED dangerous command: {shlex.quote(s)}"')
        else:
            safe_steps.append(s)
    final_cmd = " && ".join(safe_steps) if safe_steps else f'echo "[!] No executable steps"'
    print(f"[+] AI Command: {final_cmd}")
    outputs = []
    for s in safe_steps:
        out = run_command(s)
        outputs.append(f"$ {s}\n{out}")
    full_out = "\n\n".join(outputs)
    print("\n--- OUTPUT ---\n" + full_out + "\n--------------")
    mem["turns"].append({"user": user_prompt, "cmd": final_cmd, "out": full_out})
    if len(mem["turns"]) > 400:
        mem["turns"] = mem["turns"][-400:]
    save_memory(mem)

if __name__ == "__main__":
    main()
