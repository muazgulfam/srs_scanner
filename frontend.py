import threading
import queue
import time
import re
import os
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, font
import requests
from PyPDF2 import PdfReader

# ---------------------------
# Configuration
# ---------------------------
API_URL = "http://localhost:8000/analyze_pdf"  # <-- Set to your FastAPI endpoint
RETRY_INTERVAL = 3        # seconds between retry attempts
TIMEOUT_SECS = 45         # how long to wait total for LLM API before showing default message
LOCAL_HEURISTIC_WEIGHT = 0.35  # fraction of shown result initially from local heuristic
# ---------------------------


# ---------------------------
# Utilities: local heuristic analysis
# ---------------------------
IEEE_KEYWORDS = [
    r"\bAbstract\b",
    r"\bIndex Terms\b|\bKeywords\b",
    r"\bIntroduction\b",
    r"\bConclusion\b|\bConclusions\b",
    r"\bReferences\b",
    r"\bFig\.?\s*\d",  # Figure numbering style
    r"\b\d+\.\s?[A-Z]"  # numbered sections like 1. Introduction
]
CITATION_PATTERN = re.compile(r"\[\d+\]")  # [1] style
DOI_PATTERN = re.compile(r"10\.\d{4,9}/[-._;()/:A-Za-z0-9]+")  # crude DOI pattern


def extract_text_by_page(pdf_path):
    text_pages = []
    try:
        reader = PdfReader(pdf_path)
        for p in reader.pages:
            try:
                txt = p.extract_text() or ""
            except Exception:
                txt = ""
            text_pages.append(txt)
    except Exception as e:
        print("PDF read error:", e)
        return []
    return text_pages


def heuristic_ieee_analysis(pdf_path):
    """
    Returns:
      score_percent (0-100),
      missing_sections -> list of dicts: {'page':p, 'hint':str, 'snippet':str}
    This is a quick heuristic (not perfect) to give the user immediate feedback.
    """
    pages = extract_text_by_page(pdf_path)
    if not pages:
        return 0.0, [{"page": 0, "hint": "Could not read PDF text", "snippet": ""}]
    total_pages = len(pages)
    found_flags = {k: False for k in IEEE_KEYWORDS}
    pages_missing = []

    # Check presence across whole document
    fulltext = "\n".join(pages)
    for pat in IEEE_KEYWORDS:
        if re.search(pat, fulltext, flags=re.IGNORECASE):
            found_flags[pat] = True

    # Check citations, DOI
    has_citation = bool(CITATION_PATTERN.search(fulltext))
    has_doi = bool(DOI_PATTERN.search(fulltext))

    # Page-level missing hints: find pages lacking Abstract/Index Terms/References etc.
    # We'll point to pages where 'Abstract' or 'Introduction' should be near start but missing.
    # Heuristic: look at first 3 pages and last 2 pages.
    pages_to_check = list(range(min(3, total_pages))) + list(range(max(0, total_pages - 2), total_pages))
    seen_abstract = False
    for pnum in pages_to_check:
        text = pages[pnum].strip()
        snippet = (text[:300] + "...") if len(text) > 300 else text
        hints = []
        if pnum == 0:
            # first page should have Abstract
            if not re.search(r"\bAbstract\b", text, flags=re.IGNORECASE):
                hints.append("Missing 'Abstract' on first page")
            # index terms often follow abstract
            if not (re.search(r"\bIndex Terms\b|\bKeywords\b", text, flags=re.IGNORECASE) or re.search(r"\bAbstract\b", text, flags=re.IGNORECASE)):
                hints.append("No 'Index Terms' / 'Keywords' found near start")
        if pnum >= total_pages - 2:
            # last pages should include References
            if not re.search(r"\bReferences\b", text, flags=re.IGNORECASE) and not re.search(r"\[\d+\]", text):
                hints.append("References or citation list not found on last pages")
        if hints:
            pages_missing.append({"page": pnum + 1, "hint": "; ".join(hints), "snippet": snippet})

    # Score calculation (crude)
    checks = []
    # Each keyword found adds to checks
    for pat, found in found_flags.items():
        checks.append(1 if found else 0)
    checks.append(1 if has_citation else 0)
    checks.append(1 if has_doi else 0)
    score = (sum(checks) / len(checks)) * 100.0

    # If many pages in 'pages_missing', penalize
    penalty = min(len(pages_missing) * 5, 25)
    score = max(0.0, score - penalty)

    return round(score, 1), pages_missing


# ---------------------------
# Networking: send PDF to FastAPI endpoint in background with retries
# ---------------------------
def send_pdf_to_api(pdf_path, result_queue, stop_event):
    """
    Posts the PDF to API_URL. Retries until successful or stop_event is set.
    Puts ('success', data) or ('error', message) into result_queue when done.
    """
    start_time = time.time()
    files = None
    while not stop_event.is_set():
        try:
            with open(pdf_path, "rb") as f:
                files = {"file": (os.path.basename(pdf_path), f, "application/pdf")}
                # It's common to include additional JSON or params; modify if required by your API
                resp = requests.post(API_URL, files=files, timeout=15)
            if resp.status_code == 200:
                try:
                    j = resp.json()
                    result_queue.put(("success", j))
                except Exception as e:
                    result_queue.put(("error", f"Invalid JSON from API: {e}"))
                return
            else:
                # some servers respond with 4xx/5xx until they're ready
                err_msg = f"API returned status {resp.status_code}: {resp.text[:200]}"
                print(err_msg)
                # keep retrying unless time exceeds
        except requests.exceptions.RequestException as e:
            print("Request exception (will retry):", e)
        # check timeout
        elapsed = time.time() - start_time
        if elapsed > TIMEOUT_SECS:
            result_queue.put(("timeout", f"No response from API after {TIMEOUT_SECS} seconds."))
            return
        # sleep before retry
        for _ in range(RETRY_INTERVAL):
            if stop_event.is_set():
                return
            time.sleep(1)
    # if stopped externally
    result_queue.put(("stopped", "Stopped before completion."))


# ---------------------------
# Tkinter UI
# ---------------------------
class IEEECheckerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IEEE Format Checker — Instant heuristic + LLM analysis")
        self.geometry("900x640")
        self.minsize(800, 540)
        self.configure(bg="#f4f6fb")
        self.style = ttk.Style(self)
        # Use 'clam' for nicer widgets on many platforms
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        # Fonts
        self.header_font = font.Font(family="Helvetica", size=18, weight="bold")
        self.sub_font = font.Font(family="Helvetica", size=10)
        self.mono_font = font.Font(family="Courier", size=10)

        # Data
        self.current_pdf_path = None
        self.api_thread = None
        self.stop_event = threading.Event()
        self.result_q = queue.Queue()

        self.build_ui()
        self.check_result_queue_periodically()

    def build_ui(self):
        # Top frame: title + upload
        top = ttk.Frame(self, padding=(16, 12))
        top.pack(side="top", fill="x")

        title = ttk.Label(top, text="IEEE Format Checker", font=self.header_font)
        title.pack(side="left", padx=(6, 12))

        subtitle = ttk.Label(top, text="Upload a PDF to check IEEE formatting. Fast local check + LLM verification.", font=self.sub_font, foreground="#555")
        subtitle.pack(side="left", padx=6)

        upload_btn = ttk.Button(top, text="Upload PDF", command=self.upload_pdf)
        upload_btn.pack(side="right")

        # Middle frame: main content
        main = ttk.Frame(self, padding=(16, 8))
        main.pack(side="top", fill="both", expand=True)

        # Left: preview / results
        left = ttk.Frame(main)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))

        # Heuristic result box
        hframe = ttk.LabelFrame(left, text="Quick local heuristic (instant)", padding=(12, 12))
        hframe.pack(side="top", fill="x", pady=(0, 8))

        self.local_score_var = tk.StringVar(value="No PDF uploaded")
        score_label = ttk.Label(hframe, textvariable=self.local_score_var, font=font.Font(size=14, weight="bold"))
        score_label.pack(side="left")

        self.local_details = scrolledtext.ScrolledText(hframe, height=6, wrap="word", font=self.mono_font)
        self.local_details.pack(side="bottom", fill="x", pady=(8, 0))

        # Spinner & API status
        apiframe = ttk.LabelFrame(left, text="LLM API status", padding=(12, 12))
        apiframe.pack(side="top", fill="x", pady=(8, 8))

        self.api_status_var = tk.StringVar(value="Idle — upload a PDF to start LLM verification")
        self.api_status_label = ttk.Label(apiframe, textvariable=self.api_status_var)
        self.api_status_label.pack(side="left")

        # Spinner canvas
        self.spinner_canvas = tk.Canvas(apiframe, width=36, height=36, bg="#f4f6fb", highlightthickness=0)
        self.spinner_canvas.pack(side="right")
        self.spinner_angle = 0
        self._animate_spinner = False

        # Right: Detailed results from LLM (or fallback)
        right = ttk.Frame(main)
        right.pack(side="right", fill="both", expand=True)

        result_frame = ttk.LabelFrame(right, text="Final LLM result (when available)", padding=(12, 12))
        result_frame.pack(side="top", fill="both", expand=True)

        self.final_score_var = tk.StringVar(value="No LLM result yet")
        final_score_label = ttk.Label(result_frame, textvariable=self.final_score_var, font=font.Font(size=16, weight="bold"))
        final_score_label.pack(anchor="w")

        self.notes_text = scrolledtext.ScrolledText(result_frame, height=14, wrap="word")
        self.notes_text.pack(fill="both", expand=True, pady=(6, 0))

        missing_frame = ttk.LabelFrame(right, text="Where IEEE format appears missing (pages / hints)", padding=(12, 12))
        missing_frame.pack(side="top", fill="both", expand=True, pady=(8, 0))

        self.missing_list = tk.Listbox(missing_frame, height=8)
        self.missing_list.pack(fill="both", expand=True)

        # Bottom: control / help
        bottom = ttk.Frame(self, padding=(12, 8))
        bottom.pack(side="bottom", fill="x")

        self.default_message_var = tk.StringVar(value=f"No response from LLM after {TIMEOUT_SECS} seconds.")
        default_label = ttk.Label(bottom, textvariable=self.default_message_var, font=self.sub_font, foreground="#b00")
        default_label.pack(side="left")

        help_btn = ttk.Button(bottom, text="API Config / Help", command=self.show_help)
        help_btn.pack(side="right")

    def upload_pdf(self):
        path = filedialog.askopenfilename(title="Select PDF file", filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")])
        if not path:
            return
        self.current_pdf_path = path
        self.local_score_var.set("Running local heuristic...")
        self.local_details.delete("1.0", tk.END)
        self.final_score_var.set("Waiting for LLM result...")
        self.notes_text.delete("1.0", tk.END)
        self.missing_list.delete(0, tk.END)
        self.api_status_var.set("Starting LLM verification...")

        # Perform local heuristic quickly
        try:
            local_score, missing = heuristic_ieee_analysis(path)
            self.local_score_var.set(f"Local heuristic IEEE score: {local_score}%")
            txt = f"Quick missing hints (showing a few):\n"
            if missing:
                for m in missing:
                    txt += f"- Page {m['page']}: {m['hint']}\n  Snippet: {m['snippet'][:200]}\n"
            else:
                txt += "No obvious missing sections found in heuristic scan.\n"
            txt += "\n(Local checks look for headings like Abstract, Index Terms, References, figure numbers, citation markers, DOI.)"
            self.local_details.insert("1.0", txt)
        except Exception as e:
            self.local_score_var.set("Local heuristic failed")
            self.local_details.insert("1.0", f"Error running heuristic: {e}")

        # Kick off background thread to send to API
        # If any previous thread is running, stop it first
        if self.api_thread and self.api_thread.is_alive():
            self.stop_event.set()
            self.api_thread.join(timeout=1)

        # reset stop event and queue
        self.stop_event = threading.Event()
        self.result_q = queue.Queue()

        self.api_thread = threading.Thread(target=send_pdf_to_api, args=(path, self.result_q, self.stop_event), daemon=True)
        self.api_thread.start()

        # start spinner
        self._animate_spinner = True
        self.animate_spinner()

        # update status
        self.api_status_var.set("Contacting LLM API — waiting for response...")

    def animate_spinner(self):
        # draws a spinner arc that rotates
        c = self.spinner_canvas
        c.delete("all")
        center = 18
        r = 14
        # draw 4 arcs of graduated width to show motion
        for i in range(6):
            ang = (self.spinner_angle + i * 30) % 360
            extent = 30
            alpha = int(255 * (i + 1) / 6)
            # convert alpha to hex grey-ish (can't do alpha easily in canvas; vary width instead)
            width = 1 + i
            c.create_arc(center - r, center - r, center + r, center + r, start=ang, extent=extent, style="arc", width=width)
        self.spinner_angle = (self.spinner_angle + 12) % 360
        if self._animate_spinner:
            self.after(60, self.animate_spinner)

    def stop_spinner(self):
        self._animate_spinner = False
        self.spinner_canvas.delete("all")

    def check_result_queue_periodically(self):
        try:
            result = self.result_q.get_nowait()
        except queue.Empty:
            # nothing yet
            self.after(200, self.check_result_queue_periodically)
            return
        # got something
        status, payload = result
        if status == "success":
            self.handle_api_result(payload)
        elif status == "timeout":
            # stop spinner and show default message
            self.stop_spinner()
            self.api_status_var.set("No response from LLM (timeout). Showing local heuristic results.")
            self.final_score_var.set(self.default_message_var.get())
            self.notes_text.insert("1.0", "LLM did not respond in time. You can try again or check API endpoint.\n")
        elif status == "error":
            self.stop_spinner()
            self.api_status_var.set("Error from API")
            self.final_score_var.set("API error")
            self.notes_text.insert("1.0", str(payload))
        elif status == "stopped":
            self.stop_spinner()
            self.api_status_var.set("Operation stopped")
        else:
            self.stop_spinner()
            self.api_status_var.set("Unknown result")
            self.notes_text.insert("1.0", str(payload))

    def handle_api_result(self, json_data):
        """
        Parse API response and update UI. Expected format (example):
        {
          "ieee_score": 82.5,
          "missing_sections": [{"page": 2, "hint": "No 'Index Terms' or 'Keywords' found", "snippet": "..."}, ...],
          "notes": "Optional free-text notes from the LLM"
        }
        """
        self.stop_spinner()
        self.api_status_var.set("LLM responded")
        # Safely extract keys
        score = None
        missing = None
        notes = None
        try:
            score = json_data.get("ieee_score", None)
            missing = json_data.get("missing_sections", None)
            notes = json_data.get("notes", None)
        except Exception:
            # Might not be a dict - try to present raw
            notes = str(json_data)

        # Combine local heuristic for initial reading if API score missing
        if score is None:
            # use local heuristic as fallback
            if self.current_pdf_path:
                local_score, _ = heuristic_ieee_analysis(self.current_pdf_path)
                score = f"{local_score} (local heuristic)"
            else:
                score = "N/A"

        self.final_score_var.set(f"IEEE score (LLM): {score}%")
        self.notes_text.delete("1.0", tk.END)
        if notes:
            self.notes_text.insert("1.0", str(notes) + "\n\n")
        self.notes_text.insert("end", f"Raw LLM response:\n{json_data}\n")

        # Update missing list
        self.missing_list.delete(0, tk.END)
        if missing:
            for m in missing:
                page = m.get("page", "?")
                hint = m.get("hint", "No hint")
                snippet = m.get("snippet", "")
                display = f"Page {page}: {hint}"
                self.missing_list.insert(tk.END, display)
        else:
            self.missing_list.insert(tk.END, "LLM did not report missing sections (or none found).")

    def show_help(self):
msg = (
    "How to use:\n\n"
    "1) Click 'Upload PDF' and choose a PDF.\n"
    "2) A quick local heuristic will run instantly and show a local score.\n"
    "3) The app will post the PDF to your FastAPI LLM endpoint (API_URL) and wait for a JSON response.\n"
    "4) If the API does not respond within the configured TIMEOUT, a default 'No response' message is shown.\n\n"
    "Configuration:\n"
    f"- API endpoint in script: {API_URL}
    f"- Retry interval (seconds): {RETRY_INTERVAL}\n"
    f"- Timeout (seconds): {TIMEOUT_SECS}\n\n"
    "Expected API JSON (example):\n"
    '{"ieee_score": 82.5, "missing_sections": [{"page": 2, "hint": "No Index Terms", "snippet": "..."}], "notes": "..."}\n\n'
    "If your FastAPI expects a different form (e.g., JSON upload), modify send_pdf_to_api() accordingly."
)

        messagebox.showinfo("Help / API Config", msg)


if __name__ == "__main__":
    app = IEEECheckerApp()
    app.mainloop()