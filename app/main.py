import re
import base64
import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI()

class ChatRequest(BaseModel):
    message: str

# Regex patterns that catch leetspeak, noise characters, and variations
PATTERNS = [
    r'i+g+n+o+r+e+',          # ignore, iginore, iiggnnoorree
    r'p+r+e+v+i+o+u+s+',      # previous
    r'i+n+s+t+r+u+c+t+i+o+n+s+', # instructions
    r'd+i+s+r+e+g+a+r+d+',    # disregard
    r'b+y+p+a+s+s+',          # bypass
    r'j+a+i+l+b+r+e+a+k+',    # jailbreak
    r'o+v+e+r+r+i+d+e+'       # override
]

LEET_MAP = str.maketrans({
    '0':'o', '1':'i', '3':'e', '4':'a', '5':'s', '7':'t',
    '@':'a', '$':'s', '!':'i', '|':'i', '+':'t'
})

def aggressive_decode(text: str) -> str:
    """Extracts raw string, stripped base64, and sliding offset decodes."""
    fragments = [text]
    
    # Strip whitespace & non-base64 chars
    clean_b64 = re.sub(r'[^A-Za-z0-9+/=]', '', text)
    
    candidates = set(re.findall(r'[A-Za-z0-9+/=]{4,}', text))
    candidates.add(clean_b64)
    
    # Sliding window slices for offset Base64
    for cand in list(candidates):
        if len(cand) > 4:
            for shift in range(1, 4):
                candidates.add(cand[shift:])
                
    for cand in candidates:
        for pad in range(4):
            try:
                decoded = base64.b64decode(cand + ('=' * pad), validate=False).decode('utf-8', errors='ignore')
                if any(c.isalpha() for c in decoded):
                    fragments.append(decoded)
            except Exception:
                pass
                
    return " ".join(fragments)

def heuristic_scan(text: str) -> bool:
    # 1. Expand Base64
    expanded = aggressive_decode(text)
    
    # 2. Translate Leetspeak & convert to lowercase
    unleeted = expanded.lower().translate(LEET_MAP)
    
    # 3. Test regex patterns against entire unleashed text stream
    matches = 0
    for pattern in PATTERNS:
        if re.search(pattern, unleeted):
            matches += 1
            # If high-severity single word like instructions/jailbreak or 2+ tokens found
            if pattern in [r'i+n+s+t+r+u+c+t+i+o+n+s+', r'j+a+i+l+b+r+e+a+k+', r'o+v+e+r+r+i+d+e+'] or matches >= 2:
                return True
                
    return False

# ==========================================
# OPTION B: SEMANTIC ML CLASSIFIER
# ==========================================
ml_pipeline = None
ML_ENABLED = os.getenv("ENABLE_ML", "true").lower() == "true"

if ML_ENABLED:
    try:
        from transformers import pipeline
        print("\n[AI] Loading ML Classifier...")
        ml_pipeline = pipeline("text-classification", model="protectai/deberta-v3-base-prompt-injection-v2")
        print("[AI] ML Classifier loaded successfully!\n")
    except Exception as e:
        print(f"[AI] ML Model failed to load: {e}")

def ml_scan(text: str) -> bool:
    if not ml_pipeline:
        return False
    try:
        expanded = aggressive_decode(text)
        for target in [text, expanded]:
            result = ml_pipeline(target[:512]) 
            if result[0]['label'] == 'INJECTION' and result[0]['score'] > 0.65:
                return True
    except Exception:
        pass
    return False

# ==========================================
# HYBRID PIPELINE
# ==========================================
def check_prompt_injection(text: str) -> bool:
    if heuristic_scan(text):
        print(f"🛡️ [Option A] Blocked heuristic match: {text[:40]}...")
        return True
        
    if ml_scan(text):
        print(f"🛡️ [Option B] Blocked ML match: {text[:40]}...")
        return True
        
    return False

@app.post("/v1/chat")
@app.post("/chat")
@app.post("/api/chat")
async def chat_endpoint(payload: ChatRequest):
    is_injected = check_prompt_injection(payload.message)
    
    if is_injected:
        return {
            "reply": "⚠️ Security Alert: Prompt injection or jailbreak attempt detected and blocked by PromptShield.",
            "security": {"injection_flagged": True}
        }
        
    return {
        "reply": "[mock-claude-sonnet-5] Received and processed your message safely.",
        "security": {"injection_flagged": False}
    }

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}

app.mount("/", StaticFiles(directory="app/static", html=True), name="static")
