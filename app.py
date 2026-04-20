import os
import re
import logging
import base64
import threading
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from groq import Groq
from dotenv import load_dotenv
from ddgs import DDGS

load_dotenv()

# ── LOGGING ────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# ── STARTUP VALIDATION ─────────────────────────────────
GROQ_API_KEY = os.getenv('GROQ_API_KEY')
if not GROQ_API_KEY:
    raise ValueError("GROQ_API_KEY is not set. Add it to your .env file.")

# ── APP SETUP ──────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
app.config['DEBUG'] = False
app.config['TESTING'] = False
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max upload

# ── CORS ───────────────────────────────────────────────
allowed_origins = [
    "https://veris-08jl.onrender.com",
    "http://localhost:5002",
    "http://127.0.0.1:5002",
]
CORS(app, origins=allowed_origins)

# ── RATE LIMITING ──────────────────────────────────────
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day"],
    storage_uri="memory://"
)

# ── GROQ CLIENT ────────────────────────────────────────
try:
    client = Groq(api_key=GROQ_API_KEY)
except Exception as e:
    logger.error(f"Failed to initialise Groq client: {e}")
    client = None

# ── HTTPS REDIRECT ─────────────────────────────────────
@app.before_request
def force_https():
    if os.getenv('FLASK_ENV') == 'production':
        if request.headers.get('X-Forwarded-Proto') == 'http':
            from flask import redirect
            return redirect(request.url.replace('http://', 'https://'), code=301)

# ── INPUT SANITISATION ─────────────────────────────────
def sanitise(text, max_len=2000):
    if not text:
        return ""
    text = str(text).strip()[:max_len]
    text = re.sub(r'[^\x20-\x7E\n\r\t]', '', text)
    return text

def sanitise_short(text, max_len=200):
    if not text:
        return ""
    text = str(text).strip()[:max_len]
    text = re.sub(r'[^\w\s\+\-\.\@\#]', '', text)
    return text

# ── SCAM SIGNAL PATTERNS ───────────────────────────────
SCAM_PATTERNS = [
    (r'\b(send|transfer|pay|wire)\b.{0,30}\b(money|funds|bitcoin|crypto|cash|dollars|naira)\b', "money transfer request"),
    (r'\b(urgent|immediately|right now|within \d+ hour|limited time|act now|don\'t delay)\b', "urgency language"),
    (r'\b(click this link|click here|follow this link|open this url)\b', "suspicious link prompt"),
    (r'\b(you have won|you\'ve won|congratulations|selected|lucky winner|prize|lottery|award)\b', "lottery/prize scam"),
    (r'\b(keep this (secret|private|confidential)|don\'t tell anyone|between us|nobody should know)\b', "secrecy request"),
    (r'\b(i am (stuck|stranded|trapped|in trouble|in danger|in (the )?hospital))\b', "distress/emergency scenario"),
    (r'\b(investment opportunity|guaranteed (profit|return|income)|double your money|100% profit)\b', "investment scam"),
    (r'\b(verify your (account|identity|details|information)|update your (info|details|account))\b', "phishing/verification request"),
    (r'\b(gift card|itunes card|google play card|steam card|voucher code)\b', "gift card payment request"),
    (r'\b(i love you|i miss you|my love|my dear|sweetheart|honey)\b.{0,100}\b(send|money|help|need)\b', "romance scam signal"),
    (r'\bmy name is (dr|doctor|prof|general|minister|prince|princess|king|queen)\b', "fake authority/title"),
    (r'\b(inheritance|deceased|estate|next of kin|beneficiary)\b.{0,50}\b(million|billion|funds)\b', "advance fee / 419 scam"),
]

def detect_patterns(text):
    text_lower = text.lower()
    found = []
    for pattern, label in SCAM_PATTERNS:
        if re.search(pattern, text_lower):
            found.append(label)
    return list(set(found))

# ── CHECK 1: WEB SEARCH FOR PHONE/USERNAME ─────────────
def check_identifier(identifier):
    if not identifier:
        return {"found": False, "results": [], "summary": "No identifier provided"}
    try:
        results = []
        with DDGS() as ddgs:
            query = f'"{identifier}" scam fraud report'
            for r in ddgs.text(query, max_results=5):
                results.append({
                    "title": r.get("title", ""),
                    "snippet": r.get("body", "")[:200],
                    "url": r.get("href", "")
                })
        scam_keywords = ["scam", "fraud", "fake", "warning", "report", "victim", "cheat", "con"]
        hits = sum(1 for r in results if any(k in (r["title"] + r["snippet"]).lower() for k in scam_keywords))
        summary = f"Found {len(results)} results for '{identifier}'. {hits} contain scam-related content."
        return {"found": len(results) > 0, "scam_hits": hits, "results": results[:3], "summary": summary}
    except Exception as e:
        logger.error(f"Identifier check error: {e}")
        return {"found": False, "results": [], "summary": "Search unavailable"}

# ── CHECK 2: IMPERSONATION WEB SEARCH ──────────────────
def check_impersonation(name):
    if not name:
        return {"found": False, "results": [], "summary": "No name provided"}
    try:
        results = []
        with DDGS() as ddgs:
            query = f'"{name}" impersonation scam warning fake account'
            for r in ddgs.text(query, max_results=5):
                results.append({
                    "title": r.get("title", ""),
                    "snippet": r.get("body", "")[:200],
                    "url": r.get("href", "")
                })
        scam_keywords = ["scam", "fake", "impersonat", "warning", "fraud", "report"]
        hits = sum(1 for r in results if any(k in (r["title"] + r["snippet"]).lower() for k in scam_keywords))
        summary = f"Found {len(results)} web results for '{name}'. {hits} reference scam or impersonation warnings."
        return {"found": len(results) > 0, "scam_hits": hits, "results": results[:3], "summary": summary}
    except Exception as e:
        logger.error(f"Impersonation check error: {e}")
        return {"found": False, "results": [], "summary": "Search unavailable"}

# ── CHECK 3: OFFICIAL WARNING CHECK ───────────────────
def check_official_warning(name):
    if not name:
        return {"found": False, "sources": [], "statement": "No name provided."}

    strong_warning_phrases = [
        "fake account", "never dm", "do not dm", "not send dm",
        "beware of fake", "i never contact", "i do not contact",
        "not reach out", "never ask for money", "do not send money",
        "block and report", "impersonating me", "using my name",
        "fake profile", "i will never ask", "i don't dm", "i won't dm",
        "impostor", "not my account", "scam alert", "beware",
    ]

    # Only 2 queries — must complete well within the 15s thread timeout
    # Instagram first (highest hit rate for influencer warnings), then broad fallback
    queries = [
        f'site:instagram.com "{name}" fake account warning scam',
        f'"{name}" "fake account" OR "never DM" OR "impersonating" warning scam',
    ]

    results = []
    seen_urls = set()

    try:
        with DDGS() as ddgs:
            for query in queries:
                try:
                    for r in ddgs.text(query, max_results=4, timelimit='y'):
                        url = r.get("href", "")
                        if url in seen_urls:
                            continue
                        title = r.get("title", "")
                        snippet = r.get("body", "")
                        combined = (title + " " + snippet).lower()
                        name_words = [w.lower() for w in name.split() if len(w) > 2]
                        name_present = any(w in combined for w in name_words)
                        is_site_query = query.startswith("site:")
                        warning_present = any(phrase in combined for phrase in strong_warning_phrases)
                        logger.info(f"[OWC] '{title[:60]}' | name={name_present} | warning={warning_present} | site={is_site_query}")
                        if name_present and (warning_present or is_site_query):
                            seen_urls.add(url)
                            results.append({
                                "title": title,
                                "snippet": snippet[:200],
                                "url": url
                            })
                    # Early exit — found what we need
                    if results:
                        break
                except Exception as qe:
                    logger.warning(f"[OWC] Query failed: {qe}")
                    continue
    except Exception as e:
        logger.error(f"Official warning check error: {e}")

    found = len(results) > 0
    if found:
        statement = (
            f"Warning sources found: {name} or their official channels appear to have "
            f"issued public warnings about fake accounts or unsolicited DMs. "
            f"Review the sources below to confirm."
        )
    else:
        statement = (
            "No public warning found in our search. This does not rule out warnings "
            "existing elsewhere — always verify through the person's official social media or website."
        )
    return {"found": found, "sources": results[:3], "statement": statement}

# ── CHECK 4: AI CONVERSATION ANALYSIS ──────────────────
def analyse_conversation(conversation, identifier, impersonated_name):
    if not client:
        return {"error": "AI service unavailable", "signals": [], "risk_score": 0}
    patterns_found = detect_patterns(conversation)
    context = f"""You are a scam detection AI. Analyse this message for fraud signals.

Message:
{conversation}

Known context:
- Sender identifier (phone/username): {identifier or 'not provided'}
- Person being impersonated: {impersonated_name or 'not provided'}
- Pre-detected patterns: {', '.join(patterns_found) if patterns_found else 'none'}

Analyse for ALL of these scam types:
1. Advance fee fraud (419 scam) — promises of large sums requiring upfront payment
2. Romance scam — building emotional connection to extract money
3. Phishing — harvesting personal info or credentials
4. Impersonation — pretending to be a celebrity, official, bank, or authority
5. Investment fraud — guaranteed returns, crypto schemes
6. Emergency scam — fake distress to request urgent money
7. Prize/lottery scam — fake winnings requiring fees
8. Gift card scam — requesting payment via gift cards
9. Job scam — fake employment requiring payment or personal info

For each signal you find, explain it in one plain sentence that a non-technical person can understand.

Respond ONLY with valid JSON in this exact structure, no markdown:
{{
  "risk_score": <integer 0-100>,
  "scam_type": "<most likely scam type or 'unclear' or 'none detected'>",
  "signals": [
    {{"signal": "<signal name>", "explanation": "<plain one-sentence explanation>"}}
  ],
  "verdict": "<'Likely Scam' or 'Possibly Suspicious' or 'Looks Clean'>",
  "reasoning": "<2-3 plain sentences explaining the overall verdict>",
  "advice": "<one actionable sentence advising the user what to do>"
}}"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": context}],
            max_tokens=800,
            temperature=0.1
        )
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r'^```json\s*', '', raw)
        raw = re.sub(r'\s*```$', '', raw)
        import json
        result = json.loads(raw)
        result["patterns_detected"] = patterns_found
        return result
    except Exception as e:
        logger.error(f"Conversation analysis error: {e}")
        return {
            "risk_score": 50,
            "scam_type": "unknown",
            "signals": [{"signal": "Analysis error", "explanation": "AI analysis was unavailable. Proceed with caution."}],
            "verdict": "Possibly Suspicious",
            "reasoning": "Analysis could not be completed. Treat this message with caution.",
            "advice": "Do not send money or personal information until you can verify this person through another channel.",
            "patterns_detected": patterns_found
        }

# ── CHECK 4: IMAGE ANALYSIS ────────────────────────────
def analyse_image(image_b64, mime_type):
    if not client:
        return {"error": "AI service unavailable"}
    try:
        prompt = """You are a scam detection expert analysing a screenshot of a message or conversation.

Look carefully at this image and identify ALL of the following:
1. Any phone numbers, usernames, profile names, or account names visible
2. Any money amounts, payment requests, or financial information
3. Any suspicious language, urgency, or emotional manipulation
4. Any links, QR codes, or unusual attachments referenced
5. Any claims of identity (celebrity, official, banker, military, etc.)
6. Any promises of prizes, jobs, investments, or romantic interest
7. Overall visual authenticity — does this look like a real message or a fake/staged one?

Respond ONLY with valid JSON, no markdown:
{
  "identifiers_found": ["<any phone numbers, usernames visible>"],
  "scam_signals": ["<list of scam signals spotted in the image>"],
  "text_extracted": "<key text visible in the image that is relevant to scam detection>",
  "visual_red_flags": ["<anything visually suspicious — bad grammar, official-looking but fake logos, etc.>"],
  "image_verdict": "<'Likely Scam' or 'Possibly Suspicious' or 'Looks Clean' or 'Cannot Determine'>",
  "image_reasoning": "<2-3 plain sentences about what you see in the image>"
}"""

        # Only working Groq vision model — llama-3.2 vision models were decommissioned April 2025
        vision_models = [
            "meta-llama/llama-4-scout-17b-16e-instruct",
        ]
        response = None
        for vision_model in vision_models:
            try:
                response = client.chat.completions.create(
                    model=vision_model,
                    messages=[{
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {
                                "type": "image_url",
                                "image_url": {"url": f"data:{mime_type};base64,{image_b64}"}
                            },
                        ]
                    }],
                    max_tokens=600,
                    temperature=0.1
                )
                logger.info(f"Vision analysis using model: {vision_model}")
                break
            except Exception as model_err:
                logger.warning(f"Vision model {vision_model} failed: {model_err}")
                continue
        if response is None:
            raise Exception("All vision models unavailable")
        raw = response.choices[0].message.content
        if raw:
            raw = raw.strip()
        logger.info(f"Vision raw response (first 200 chars): {repr(raw[:200]) if raw else 'EMPTY'}")
        if not raw:
            raise Exception("Vision model returned empty response")
        raw = re.sub(r'^```(?:json)?\s*', '', raw)
        raw = re.sub(r'\s*```$', '', raw)
        import json
        return json.loads(raw)
    except Exception as e:
        logger.error(f"Image analysis error: {e}")
        return {
            "identifiers_found": [],
            "scam_signals": [],
            "text_extracted": "",
            "visual_red_flags": [],
            "image_verdict": "Cannot Determine",
            "image_reasoning": "Image analysis was unavailable."
        }

# ── FINAL SYNTHESIS ────────────────────────────────────
def synthesise_verdict(conversation_result, id_check, impersonation_check, image_result=None):
    if not client:
        return conversation_result

    signals_summary = []
    if id_check.get("scam_hits", 0) > 0:
        signals_summary.append(f"Phone/username appears in {id_check['scam_hits']} scam reports online")
    if impersonation_check.get("scam_hits", 0) > 0:
        signals_summary.append(f"Impersonated name found in {impersonation_check['scam_hits']} scam warnings")
    if image_result and image_result.get("scam_signals"):
        signals_summary.append(f"Image analysis found: {', '.join(image_result['scam_signals'][:3])}")

    if not signals_summary:
        return conversation_result

    try:
        import json
        synthesis_prompt = f"""Given this initial scam analysis:
Verdict: {conversation_result.get('verdict')}
Risk score: {conversation_result.get('risk_score')}
Reasoning: {conversation_result.get('reasoning')}

Additional evidence found:
{chr(10).join('- ' + s for s in signals_summary)}

Update the risk score and verdict if the additional evidence changes your assessment.
Respond ONLY with valid JSON:
{{
  "risk_score": <integer 0-100>,
  "verdict": "<'Likely Scam' or 'Possibly Suspicious' or 'Looks Clean'>",
  "reasoning": "<2-3 plain sentences incorporating all evidence>",
  "advice": "<one actionable sentence>"
}}"""

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": synthesis_prompt}],
            max_tokens=300,
            temperature=0.1
        )
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r'^```json\s*', '', raw)
        raw = re.sub(r'\s*```$', '', raw)
        update = json.loads(raw)
        conversation_result.update(update)
    except Exception as e:
        logger.error(f"Synthesis error: {e}")

    return conversation_result

# ── MAIN ANALYSE ENDPOINT ──────────────────────────────
@app.route('/analyse', methods=['POST'])
@limiter.limit("3 per minute;15 per hour;50 per day")
def analyse():
    if client is None:
        return jsonify({'error': 'An internal error occurred. Please try again.'}), 500

    data = request.get_json(silent=True)
    if not data:
        # Handle multipart form data (for image uploads)
        conversation = sanitise(request.form.get('conversation', ''))
        identifier = sanitise_short(request.form.get('identifier', ''))
        impersonated_name = sanitise_short(request.form.get('impersonated_name', ''))
        image_file = request.files.get('image')
    else:
        conversation = sanitise(data.get('conversation', ''))
        identifier = sanitise_short(data.get('identifier', ''))
        impersonated_name = sanitise_short(data.get('impersonated_name', ''))
        image_file = None

    if not conversation and not image_file:
        return jsonify({'error': 'Please provide a message or upload a screenshot.'}), 400

    if conversation and len(conversation) < 5:
        return jsonify({'error': 'Message is too short to analyse.'}), 400

    # Process image if provided
    image_result = None
    image_b64 = None
    mime_type = None
    if image_file:
        allowed_types = {'image/jpeg', 'image/png', 'image/webp'}
        mime_type = image_file.mimetype
        if mime_type not in allowed_types:
            return jsonify({'error': 'Only JPG, PNG, and WebP images are supported.'}), 400
        image_data = image_file.read()
        if len(image_data) > 4 * 1024 * 1024:
            return jsonify({'error': 'Image too large. Maximum size is 4MB.'}), 413
        image_b64 = base64.b64encode(image_data).decode('utf-8')

    # Run checks in parallel using threads
    results = {}
    errors = {}

    def run_id_check():
        try:
            results['id'] = check_identifier(identifier)
        except Exception as e:
            errors['id'] = str(e)
            results['id'] = {"found": False, "results": [], "summary": "Check unavailable"}

    def run_impersonation_check():
        try:
            results['impersonation'] = check_impersonation(impersonated_name)
        except Exception as e:
            errors['impersonation'] = str(e)
            results['impersonation'] = {"found": False, "results": [], "summary": "Check unavailable"}

    def run_official_warning_check():
        try:
            results['official_warning'] = check_official_warning(impersonated_name)
        except Exception as e:
            errors['official_warning'] = str(e)
            results['official_warning'] = {"found": False, "sources": [], "statement": "Check unavailable."}

    def run_conversation_check():
        try:
            results['conversation'] = analyse_conversation(conversation, identifier, impersonated_name)
        except Exception as e:
            errors['conversation'] = str(e)
            results['conversation'] = {"risk_score": 50, "verdict": "Possibly Suspicious", "signals": [], "reasoning": "Analysis unavailable.", "advice": "Proceed with caution."}

    def run_image_check():
        if image_b64:
            try:
                results['image'] = analyse_image(image_b64, mime_type)
            except Exception as e:
                errors['image'] = str(e)
                results['image'] = {"image_verdict": "Cannot Determine", "image_reasoning": "Image analysis unavailable."}

    threads = [
        threading.Thread(target=run_id_check),
        threading.Thread(target=run_impersonation_check),
        threading.Thread(target=run_official_warning_check),
        threading.Thread(target=run_image_check),
    ]

    # Start web searches and image analysis in parallel
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    # Run conversation analysis (uses Groq — serial to avoid TPM issues)
    run_conversation_check()

    # Synthesise all signals into final verdict
    final = synthesise_verdict(
        results.get('conversation', {}),
        results.get('id', {}),
        results.get('impersonation', {}),
        results.get('image')
    )

    # Attach official warning into impersonation_check so frontend receives it correctly
    imp_check_result = results.get('impersonation', {})
    imp_check_result['official_warning'] = results.get('official_warning', {"found": False, "sources": [], "statement": ""})

    return jsonify({
        'verdict': final.get('verdict', 'Possibly Suspicious'),
        'risk_score': final.get('risk_score', 50),
        'scam_type': final.get('scam_type', 'unknown'),
        'reasoning': final.get('reasoning', ''),
        'advice': final.get('advice', 'Proceed with caution.'),
        'signals': final.get('signals', []),
        'patterns_detected': final.get('patterns_detected', []),
        'id_check': results.get('id', {}),
        'impersonation_check': imp_check_result,
        'image_analysis': results.get('image'),
    })


# ── HEALTH CHECK ───────────────────────────────────────
@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'veris'}), 200


# ── ERROR HANDLERS ─────────────────────────────────────
@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 5MB.'}), 413

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({
        'error': 'rate_limit',
        'message': 'Too many requests. You are limited to 3 per minute and 15 per hour. Please wait and try again.'
    }), 429

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'An internal error occurred. Please try again.'}), 500


@app.route('/')
def index():
    with open(os.path.join(BASE_DIR, 'index.html'), 'r', encoding='utf-8') as f:
        return f.read(), 200, {'Content-Type': 'text/html'}


if __name__ == '__main__':
    env = os.getenv('FLASK_ENV', 'development')
    port = int(os.getenv('PORT', 5002))
    app.run(host='0.0.0.0', port=port, debug=(env == 'development'))
