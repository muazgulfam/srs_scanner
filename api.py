# app.py
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
import uvicorn
import pdfplumber
import re
import tempfile
from typing import Optional
from pydantic import BaseModel

app = FastAPI(title="IEEE Format Checker - Rule Based")

# --- rule functions
def detect_repeated_lines(pages, top_k_lines=3, threshold_ratio=0.6):
    from collections import Counter
    n_pages = len(pages)
    cand_lines = []
    for pg in pages:
        if not pg:
            continue
        lines = [ln.strip() for ln in pg.splitlines() if ln.strip()]
        cand_lines += lines[:top_k_lines]
        if len(lines) >= top_k_lines:
            cand_lines += lines[-top_k_lines:]
    c = Counter(cand_lines)
    repeated = set([ln for ln,count in c.items() if count >= max(1, int(threshold_ratio * n_pages))])
    repeated |= set([ln for ln in c.keys() if re.search(r'^\s*Page\s*\d+', ln, re.I)])
    return repeated

def clean_pages_remove_headers(pages):
    pages_cleaned = []
    repeated = detect_repeated_lines(pages)
    for pg in pages:
        if not pg:
            continue
        kept_lines = []
        for ln in pg.splitlines():
            ln_s = ln.strip()
            if not ln_s:
                continue
            if ln_s in repeated:
                continue
            if re.fullmatch(r'\d{1,3}', ln_s):
                continue
            kept_lines.append(ln_s)
        pages_cleaned.append("\n".join(kept_lines))
    final_text = "\n\n[PAGE_BREAK]\n\n".join(pages_cleaned).strip()
    final_text = re.sub(r'\s+\n', '\n', final_text)
    final_text = re.sub(r'\n\s+', '\n', final_text)
    final_text = re.sub(r'[ \t]{2,}', ' ', final_text)
    return final_text

def rule_checks(text):
    txt_low = text.lower()
    features = {}
    features['word_count'] = int(len(re.findall(r'\w+', txt_low)))
    features['abstract'] = bool(re.search(r'(^|\n)\s*abstract\b', txt_low))
    features['keywords'] = bool(re.search(r'(keywords|index terms)\s*[:—\-]?', txt_low))
    features['references_section'] = bool(re.search(r'(^|\n)\s*references\b', txt_low))
    features['bracket_citations'] = bool(re.search(r'\[\d+(?:[-,]\d+)*\]', txt_low))
    heading_list = ['introduction','methodology','methods','results','discussion','conclusion','acknowledg']
    features['heading_hits'] = sum(bool(re.search(r'(^|\n)\s*'+h+r'\b', txt_low)) for h in heading_list)
    # Score and classification
    features['score'] = sum([features['abstract'], features['keywords'], features['references_section'], features['bracket_citations'], 1 if features['heading_hits']>=2 else 0])
    features['predicted_label'] = 'IEEE' if features['score'] >= 3 else 'NON-IEEE'
    return features

def extract_text_from_pdf_bytes(content_bytes):
    pages = []
    with tempfile.NamedTemporaryFile(suffix='.pdf') as tmp:
        tmp.write(content_bytes)
        tmp.flush()
        try:
            with pdfplumber.open(tmp.name) as pdf:
                for p in pdf.pages:
                    txt = p.extract_text()
                    if txt is None:
                        txt = ""
                    pages.append(txt)
        except Exception as e:
            raise RuntimeError(f"PDF extraction failed: {e}")
    return pages

# --- Pydantic model for text endpoint ---
class TextIn(BaseModel):
    text: str

# --- Endpoints ---
@app.post("/check_pdf")
async def check_pdf(file: UploadFile = File(...)):
    if file.content_type != 'application/pdf':
        raise HTTPException(status_code=400, detail="Please upload a PDF file.")
    contents = await file.read()
    try:
        pages = extract_text_from_pdf_bytes(contents)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    cleaned = clean_pages_remove_headers(pages)
    if not cleaned:
        return JSONResponse({"error":"No extractable text — possibly scanned PDF. Consider OCR."}, status_code=200)
    features = rule_checks(cleaned)
    # produce short suggestions if NON-IEEE
    suggestions = []
    if features['predicted_label'] != 'IEEE':
        if not features['abstract']:
            suggestions.append("Add an 'Abstract' section near the start.")
        if not features['keywords']:
            suggestions.append("Add a 'Keywords' or 'Index Terms' section after Abstract.")
        if not features['bracket_citations']:
            suggestions.append("Use IEEE-style bracket citations like [1], [2].")
        if not features['references_section']:
            suggestions.append("Add a numbered 'References' section at the end.")
        if features['heading_hits'] < 2:
            suggestions.append("Include common section headings like Introduction, Methods, Results, Conclusion.")
    return {"predicted_label": features['predicted_label'], "features": features, "suggestions": suggestions}

@app.post("/check_text")
async def check_text(payload: TextIn):
    text = payload.text
    if not text or len(text.strip()) < 30:
        raise HTTPException(status_code=400, detail="Please provide longer text to check.")
    features = rule_checks(text)
    suggestions = []
    if features['predicted_label'] != 'IEEE':
        if not features['abstract']:
            suggestions.append("Add an 'Abstract' section near the start.")
        if not features['keywords']:
            suggestions.append("Add a 'Keywords' or 'Index Terms' section after Abstract.")
        if not features['bracket_citations']:
            suggestions.append("Use IEEE-style bracket citations like [1], [2].")
        if not features['references_section']:
            suggestions.append("Add a numbered 'References' section at the end.")
        if features['heading_hits'] < 2:
            suggestions.append("Include common section headings like Introduction, Methods, Results, Conclusion.")
    return {"predicted_label": features['predicted_label'], "features": features, "suggestions": suggestions}

# For running directly via `python app.py`
if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
