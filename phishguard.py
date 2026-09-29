import tkinter as tk
from tkinter import ttk, messagebox
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import socket
import ssl
import ipaddress
import csv
import json
import os
import re
import math
import threading
import webbrowser
from datetime import datetime


# ============================================================
# PHISHGUARD V13
# Advanced Phishing URL Security Analyzer
# ============================================================

APP_NAME = "PHISHGUARD"
VERSION = "V13"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(BASE_DIR, "reports")
HISTORY_FILE = os.path.join(BASE_DIR, "scan_history.csv")

os.makedirs(REPORT_DIR, exist_ok=True)


SUSPICIOUS_TLDS = {
    "click", "download", "icu", "info", "live", "loan",
    "online", "party", "review", "shop", "site", "support",
    "top", "today", "trade", "vip", "win", "work", "xyz", "zip"
}

KEYWORDS = {
    "login": 5,
    "signin": 5,
    "verify": 7,
    "verification": 7,
    "password": 6,
    "credential": 7,
    "account": 4,
    "secure": 3,
    "security": 3,
    "update": 4,
    "confirm": 5,
    "payment": 5,
    "billing": 4,
    "invoice": 4,
    "wallet": 5,
    "banking": 6,
    "recover": 5,
    "unlock": 5,
    "suspended": 8,
    "urgent": 6
}

BRANDS = [
    "paypal",
    "google",
    "microsoft",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
    "linkedin",
    "github",
    "whatsapp"
]

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
    "cutt.ly",
    "rebrand.ly"
}


# ============================================================
# UTILITIES
# ============================================================

def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_url(url):
    url = url.strip()

    if not url:
        return ""

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    return url


def calculate_entropy(text):
    if not text:
        return 0

    length = len(text)
    result = 0

    for char in set(text):
        probability = text.count(char) / length
        result -= probability * math.log2(probability)

    return round(result, 3)


def is_ip_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ============================================================
# NETWORK CHECK
# ============================================================

def fetch_url(url):

    try:
        request = Request(
            url,
            headers={
                "User-Agent":
                "Mozilla/5.0 PhishGuard Security Analyzer"
            }
        )

        context = ssl.create_default_context()

        with urlopen(
            request,
            timeout=7,
            context=context
        ) as response:

            body = response.read(
                10000
            ).decode(
                "utf-8",
                errors="ignore"
            )

            return {
                "status": response.status,
                "final_url": response.geturl(),
                "server": response.headers.get(
                    "Server",
                    ""
                ),
                "body": body
            }

    except HTTPError as error:

        return {
            "status": error.code,
            "final_url": error.geturl(),
            "error": f"HTTP {error.code}",
            "body": ""
        }

    except Exception as error:

        return {
            "status": None,
            "final_url": url,
            "error": str(error),
            "body": ""
        }


# ============================================================
# URL ANALYZER
# ============================================================

def analyze_url(raw_url):

    url = normalize_url(raw_url)

    parsed = urlparse(url)

    if parsed.scheme not in ["http", "https"]:
        raise ValueError(
            "Invalid URL. Use HTTP or HTTPS."
        )

    if not parsed.netloc:
        raise ValueError(
            "Invalid URL."
        )

    host = (
        parsed.hostname or ""
    ).lower().rstrip(".")

    score = 0
    findings = []

    def add_score(points, text):
        nonlocal score

        score += points

        findings.append(
            f"[+{points}] {text}"
        )

    # HTTPS
    if parsed.scheme != "https":
        add_score(
            8,
            "URL does not use HTTPS"
        )

    # IP address
    if is_ip_address(host):
        add_score(
            15,
            "Host is a raw IP address"
        )

    # Punycode
    if "xn--" in host:
        add_score(
            15,
            "Punycode / IDN hostname detected"
        )

    # URL length
    if len(url) > 120:
        add_score(
            8,
            f"Very long URL ({len(url)} characters)"
        )

    elif len(url) > 80:
        add_score(
            4,
            f"Long URL ({len(url)} characters)"
        )

    # Subdomains
    if host.count(".") >= 4:
        add_score(
            8,
            "Deeply nested subdomain structure"
        )

    # @ symbol
    if "@" in url:
        add_score(
            12,
            "@ symbol can obscure destination"
        )

    # Encoded characters
    if "%" in url:
        add_score(
            4,
            "Percent encoded characters detected"
        )

    # Double slash
    if "//" in parsed.path:
        add_score(
            5,
            "Double slash detected inside path"
        )

    # Host length
    if len(host) > 45:
        add_score(
            5,
            "Unusually long hostname"
        )

    # Entropy
    host_entropy = calculate_entropy(host)

    if host_entropy > 3.8:
        add_score(
            5,
            "High hostname entropy"
        )

    # TLD
    if "." in host:
        tld = host.rsplit(".", 1)[1]
    else:
        tld = host

    if tld in SUSPICIOUS_TLDS:
        add_score(
            6,
            f"Suspicious TLD detected: .{tld}"
        )

    # Keywords
    for keyword, points in KEYWORDS.items():

        if keyword in url.lower():

            add_score(
                points,
                f"Suspicious keyword: {keyword}"
            )

    # Brand impersonation
    for brand in BRANDS:

        if brand in host:

            legitimate = (
                host == f"{brand}.com"
                or host.endswith(
                    f".{brand}.com"
                )
            )

            if not legitimate:

                add_score(
                    10,
                    f"Possible {brand} brand impersonation"
                )

    # URL shorteners
    if host in SHORTENERS:

        add_score(
            7,
            "URL shortener hides destination"
        )

    # Suspicious delimiters
    delimiter_count = (
        url.count("-")
        + url.count("_")
        + url.count("=")
    )

    if delimiter_count >= 10:

        add_score(
            5,
            "High delimiter count"
        )

    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    network = {
        "dns_resolved": False,
        "ips": []
    }

    try:

        addresses = socket.getaddrinfo(
            host,
            443 if parsed.scheme == "https" else 80,
            type=socket.SOCK_STREAM
        )

        ips = sorted(
            {
                item[4][0]
                for item in addresses
            }
        )

        network["ips"] = ips
        network["dns_resolved"] = bool(ips)

    except Exception as error:

        network["dns_error"] = str(error)

        add_score(
            4,
            "DNS resolution failed"
        )

    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    response = fetch_url(url)

    network["status"] = response.get(
        "status"
    )

    network["final_url"] = response.get(
        "final_url"
    )

    network["server"] = response.get(
        "server",
        ""
    )

    # Redirect detection
    final_host = urlparse(
        response.get(
            "final_url",
            url
        )
    ).hostname

    if final_host and final_host.lower() != host:

        add_score(
            8,
            "Redirects to a different hostname"
        )

        network["redirected_host"] = final_host

    # Page content
    body = response.get(
        "body",
        ""
    ).lower()

    if body:

        password_fields = re.findall(
            r'<input[^>]+type=["\']?password',
            body
        )

        if password_fields:

            add_score(
                4,
                "Password input detected"
            )

        if re.search(
            r"login|signin|verify|credential|password",
            body
        ):

            add_score(
                3,
                "Login/verification language detected"
            )

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    score = max(
        0,
        min(
            100,
            score
        )
    )

    if score >= 75:
        risk = "CRITICAL"

    elif score >= 50:
        risk = "HIGH"

    elif score >= 25:
        risk = "MEDIUM"

    else:
        risk = "LOW"

    return {
        "time": current_time(),
        "url": url,
        "domain": host,
        "score": score,
        "risk": risk,
        "findings": findings,
        "checks": {
            "https": parsed.scheme == "https",
            "ip_host": is_ip_address(host),
            "punycode": "xn--" in host,
            "tld": tld,
            "hostname_entropy": host_entropy,
            "url_entropy": calculate_entropy(url),
            "url_length": len(url)
        },
        "network": network
    }


# ============================================================
# HISTORY
# ============================================================

def save_history(result):

    exists = os.path.exists(
        HISTORY_FILE
    )

    with open(
        HISTORY_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        if not exists:

            writer.writerow(
                [
                    "Time",
                    "Domain",
                    "Score",
                    "Risk",
                    "URL"
                ]
            )

        writer.writerow(
            [
                result["time"],
                result["domain"],
                result["score"],
                result["risk"],
                result["url"]
            ]
        )


# ============================================================
# REPORT
# ============================================================

def create_report(result):

    text = []

    text.append(
        f"PHISHGUARD {VERSION} SECURITY REPORT"
    )

    text.append("=" * 65)

    text.append(
        f"TIME: {result['time']}"
    )

    text.append(
        f"URL: {result['url']}"
    )

    text.append(
        f"DOMAIN: {result['domain']}"
    )

    text.append(
        f"RISK SCORE: {result['score']}/100"
    )

    text.append(
        f"RISK LEVEL: {result['risk']}"
    )

    text.append("")

    text.append(
        "SECURITY FINDINGS"
    )

    text.append("-" * 65)

    if result["findings"]:

        text.extend(
            result["findings"]
        )

    else:

        text.append(
            "No suspicious heuristic detected."
        )

    text.append("")

    text.append(
        "TECHNICAL CHECKS"
    )

    text.append("-" * 65)

    text.append(
        json.dumps(
            result["checks"],
            indent=2
        )
    )

    text.append("")

    text.append(
        "NETWORK INFORMATION"
    )

    text.append("-" * 65)

    text.append(
        json.dumps(
            result["network"],
            indent=2
        )
    )

    return "\n".join(text)


def save_report_files(result):

    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    base = os.path.join(
        REPORT_DIR,
        f"phishguard_{stamp}"
    )

    with open(
        base + ".txt",
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            create_report(result)
        )

    with open(
        base + ".json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            result,
            file,
            indent=2
        )

    return base


# ============================================================
# GUI
# ============================================================

class PhishGuardApp:

    def __init__(self, root):

        self.root = root

        self.root.title(
            f"{APP_NAME} {VERSION} - Advanced URL Security Analyzer"
        )

        self.root.geometry(
            "1250x820"
        )

        self.root.configure(
            bg="#0b1324"
        )

        self.last_result = None

        self.search_var = tk.StringVar()

        self.status_var = tk.StringVar(
            value="Ready"
        )

        self.build_ui()

        self.load_history()

    # --------------------------------------------------------

    def button(
        self,
        parent,
        text,
        command,
        color
    ):

        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=color,
            fg="white",
            activebackground=color,
            activeforeground="white",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padx=14,
            pady=9,
            cursor="hand2"
        )

    # --------------------------------------------------------

    def build_ui(self):

        tk.Label(
            self.root,
            text="🛡",
            font=("Segoe UI Emoji", 42),
            bg="#0b1324",
            fg="white"
        ).pack(
            pady=(15, 0)
        )

        tk.Label(
            self.root,
            text=APP_NAME,
            font=("Segoe UI", 30, "bold"),
            bg="#0b1324",
            fg="white"
        ).pack()

        tk.Label(
            self.root,
            text=f"{VERSION} • Advanced Phishing URL Security Dashboard",
            font=("Segoe UI", 12),
            bg="#0b1324",
            fg="#91a4c6"
        ).pack()

        # URL
        top = tk.Frame(
            self.root,
            bg="#0b1324"
        )

        top.pack(
            fill="x",
            padx=50,
            pady=15
        )

        self.url_entry = tk.Entry(
            top,
            font=("Segoe UI", 15),
            bg="#34445f",
            fg="white",
            insertbackground="white",
            relief="flat"
        )

        self.url_entry.pack(
            fill="x",
            ipady=13
        )

        self.url_entry.bind(
            "<Return>",
            lambda event: self.analyze()
        )

        # Buttons
        toolbar = tk.Frame(
            self.root,
            bg="#0b1324"
        )

        toolbar.pack()

        buttons = [
            ("🔍 ANALYZE", self.analyze, "#2563eb"),
            ("🧪 TEST", self.test_url, "#7c3aed"),
            ("📋 COPY", self.copy_report, "#0891b2"),
            ("💾 SAVE REPORT", self.save_report, "#059669"),
            ("📂 OPEN REPORT", self.open_report, "#475569"),
            ("✕ CLEAR", self.clear, "#475569"),
            ("🗑 HISTORY", self.clear_history, "#b91c1c")
        ]

        for text, command, color in buttons:

            self.button(
                toolbar,
                text,
                command,
                color
            ).pack(
                side="left",
                padx=3
            )

        # Statistics
        statistics = tk.Frame(
            self.root,
            bg="#17243b"
        )

        statistics.pack(
            fill="x",
            padx=30,
            pady=15
        )

        self.stat_labels = {}

        stats = [
            ("total", "TOTAL SCANS", "#3b82f6"),
            ("low", "LOW", "#10b981"),
            ("medium", "MEDIUM", "#f59e0b"),
            ("high", "HIGH", "#f97316"),
            ("critical", "CRITICAL", "#ef4444")
        ]

        for key, title, color in stats:

            frame = tk.Frame(
                statistics,
                bg="#17243b"
            )

            frame.pack(
                side="left",
                expand=True,
                pady=10
            )

            tk.Label(
                frame,
                text=title,
                bg="#17243b",
                fg="#9fb0ca",
                font=("Segoe UI", 9, "bold")
            ).pack()

            label = tk.Label(
                frame,
                text="0",
                bg="#17243b",
                fg=color,
                font=("Segoe UI", 23, "bold")
            )

            label.pack()

            self.stat_labels[key] = label

        # Main
        main = tk.Frame(
            self.root,
            bg="#0b1324"
        )

        main.pack(
            fill="both",
            expand=True,
            padx=30
        )

        # Left
        left = tk.Frame(
            main,
            bg="#17243b"
        )

        left.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 6)
        )

        header = tk.Frame(
            left,
            bg="#17243b"
        )

        header.pack(
            fill="x"
        )

        self.score_label = tk.Label(
            header,
            text="-- / 100",
            bg="#17243b",
            fg="white",
            font=("Segoe UI", 28, "bold")
        )

        self.score_label.pack(
            side="left",
            padx=20,
            pady=15
        )

        self.risk_label = tk.Label(
            header,
            text="WAITING",
            bg="#17243b",
            fg="#aebbd0",
            font=("Segoe UI", 22, "bold")
        )

        self.risk_label.pack(
            side="right",
            padx=20
        )

        self.progress = ttk.Progressbar(
            left,
            maximum=100
        )

        self.progress.pack(
            fill="x",
            padx=20
        )

        tk.Label(
            left,
            text="SECURITY ANALYSIS",
            bg="#17243b",
            fg="white",
            font=("Segoe UI", 13, "bold")
        ).pack(
            anchor="w",
            padx=20,
            pady=8
        )

        self.report_box = tk.Text(
            left,
            bg="#0f1b30",
            fg="#dbe7ff",
            font=("Consolas", 10),
            relief="flat",
            wrap="word"
        )

        self.report_box.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=8
        )

        # Right
        right = tk.Frame(
            main,
            bg="#17243b"
        )

        right.pack(
            side="right",
            fill="both",
            expand=True,
            padx=(6, 0)
        )

        tk.Label(
            right,
            text="SCAN HISTORY",
            bg="#17243b",
            fg="white",
            font=("Segoe UI", 13, "bold")
        ).pack(
            anchor="w",
            padx=15,
            pady=12
        )

        search_frame = tk.Frame(
            right,
            bg="#17243b"
        )

        search_frame.pack(
            fill="x",
            padx=15
        )

        tk.Entry(
            search_frame,
            textvariable=self.search_var,
            bg="#34445f",
            fg="white",
            insertbackground="white",
            relief="flat"
        ).pack(
            side="left",
            fill="x",
            expand=True,
            ipady=8
        )

        self.button(
            search_frame,
            "SEARCH",
            self.load_history,
            "#2563eb"
        ).pack(
            side="right",
            padx=5
        )

        self.history = ttk.Treeview(
            right,
            columns=(
                "time",
                "domain",
                "score",
                "risk",
                "url"
            ),
            show="headings"
        )

        widths = {
            "time": 140,
            "domain": 180,
            "score": 60,
            "risk": 80,
            "url": 280
        }

        for column in widths:

            self.history.heading(
                column,
                text=column.upper()
            )

            self.history.column(
                column,
                width=widths[column]
            )

        self.history.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=10
        )

        self.history.bind(
            "<Double-1>",
            self.history_double_click
        )

        tk.Label(
            self.root,
            textvariable=self.status_var,
            bg="#0b1324",
            fg="#8fa4c4",
            anchor="w"
        ).pack(
            fill="x",
            padx=30,
            pady=5
        )

    # ========================================================
    # ACTIONS
    # ========================================================

    def analyze(self):

        url = self.url_entry.get().strip()

        if not url:

            messagebox.showwarning(
                "PhishGuard",
                "Enter a URL first."
            )

            return

        self.risk_label.config(
            text="SCANNING",
            fg="#60a5fa"
        )

        self.status_var.set(
            "Analyzing URL..."
        )

        threading.Thread(
            target=self.worker,
            args=(url,),
            daemon=True
        ).start()

    def worker(self, url):

        try:

            result = analyze_url(url)

            save_history(result)

            save_report_files(result)

            self.root.after(
                0,
                lambda: self.show_result(result)
            )

        except Exception as error:

            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "PhishGuard Error",
                    str(error)
                )
            )

    def show_result(self, result):

        self.last_result = result

        self.score_label.config(
            text=f"{result['score']} / 100"
        )

        colors = {
            "LOW": "#10b981",
            "MEDIUM": "#f59e0b",
            "HIGH": "#f97316",
            "CRITICAL": "#ef4444"
        }

        self.risk_label.config(
            text=result["risk"],
            fg=colors[result["risk"]]
        )

        self.progress["value"] = result["score"]

        self.report_box.delete(
            "1.0",
            "end"
        )

        self.report_box.insert(
            "1.0",
            create_report(result)
        )

        self.status_var.set(
            f"Scan complete • {result['domain']} • "
            f"{result['score']}/100 • {result['risk']}"
        )

        self.load_history()

    def test_url(self):

        self.url_entry.delete(
            0,
            "end"
        )

        self.url_entry.insert(
            0,
            "https://paypal-login-security.example.com/verify?urgent=1"
        )

        self.analyze()

    def copy_report(self):

        text = self.report_box.get(
            "1.0",
            "end-1c"
        )

        self.root.clipboard_clear()

        self.root.clipboard_append(
            text
        )

        self.status_var.set(
            "Report copied to clipboard"
        )

    def save_report(self):

        if not self.last_result:

            messagebox.showinfo(
                "PhishGuard",
                "Run a scan first."
            )

            return

        path = save_report_files(
            self.last_result
        )

        messagebox.showinfo(
            "Report Saved",
            f"Report saved:\n{path}"
        )

    def open_report(self):

        reports = [
            os.path.join(
                REPORT_DIR,
                file
            )
            for file in os.listdir(REPORT_DIR)
            if file.endswith(".html")
        ]

        if not reports:

            messagebox.showinfo(
                "PhishGuard",
                "No HTML reports found."
            )

            return

        latest = max(
            reports,
            key=os.path.getmtime
        )

        webbrowser.open(
            "file:///" +
            latest.replace("\\", "/")
        )

    def clear(self):

        self.url_entry.delete(
            0,
            "end"
        )

        self.report_box.delete(
            "1.0",
            "end"
        )

        self.score_label.config(
            text="-- / 100"
        )

        self.risk_label.config(
            text="WAITING",
            fg="#aebbd0"
        )

        self.progress["value"] = 0

        self.last_result = None

        self.status_var.set(
            "Ready"
        )

    # ========================================================
    # HISTORY
    # ========================================================

    def load_history(self):

        for item in self.history.get_children():

            self.history.delete(
                item
            )

        counts = {
            "total": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0
        }

        if not os.path.exists(
            HISTORY_FILE
        ):

            return

        try:

            with open(
                HISTORY_FILE,
                encoding="utf-8"
            ) as file:

                rows = list(
                    csv.DictReader(file)
                )

            search = (
                self.search_var.get()
                .lower()
            )

            for row in reversed(rows):

                combined = (
                    row["Time"]
                    + row["Domain"]
                    + row["Risk"]
                    + row["URL"]
                ).lower()

                if search and search not in combined:
                    continue

                self.history.insert(
                    "",
                    "end",
                    values=(
                        row["Time"],
                        row["Domain"],
                        row["Score"],
                        row["Risk"],
                        row["URL"]
                    )
                )

                counts["total"] += 1

                risk = row["Risk"].lower()

                if risk in counts:
                    counts[risk] += 1

        except Exception:
            pass

        for key in counts:

            self.stat_labels[key].config(
                text=str(
                    counts[key]
                )
            )

    def history_double_click(
        self,
        event=None
    ):

        selection = self.history.selection()

        if not selection:
            return

        values = self.history.item(
            selection[0],
            "values"
        )

        if len(values) >= 5:

            self.url_entry.delete(
                0,
                "end"
            )

            self.url_entry.insert(
                0,
                values[4]
            )

            self.analyze()

    def clear_history(self):

        confirm = messagebox.askyesno(
            "Clear History",
            "Delete complete scan history?"
        )

        if not confirm:
            return

        try:

            if os.path.exists(
                HISTORY_FILE
            ):
                os.remove(
                    HISTORY_FILE
                )

        except Exception as error:

            messagebox.showerror(
                "Error",
                str(error)
            )

        self.load_history()


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    root = tk.Tk()

    app = PhishGuardApp(
        root
    )

    root.mainloop()