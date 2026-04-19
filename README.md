# Veris — AI Scam Detection Agent

Paste a suspicious message. Veris runs three simultaneous checks and tells you exactly what it found.

## How it works

1. **Scam database check** — searches known scam databases for the phone number or username
2. **Impersonation check** — searches the web for public warnings about the person being impersonated
3. **AI pattern analysis** — LLaMA 3.3 70B reads the conversation and detects scam signals

Returns one of three verdicts: **Likely Scam / Possibly Suspicious / Looks Clean**

## Setup

```bash
git clone https://github.com/kvng-subomii/veris.git
cd veris
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
cp .env.example .env   # Add your GROQ_API_KEY
python app.py
```

Open http://127.0.0.1:5002

## API Keys

- **Groq** (required): https://console.groq.com — free tier
- **NumVerify** (optional): https://numverify.com — phone validation

## Tech Stack

Python · Flask · Groq · LLaMA 3.3 70B · DDGS · Vanilla HTML/CSS/JS

## Built by

Oleghe Olaoluwasubomi Godwin — Project 3 of 3
