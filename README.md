# Threat Scanner — Gmail Add-on Email Analyzer

Project Git Link - https://github.com/lavital11/gmail-threat-scanner

A real-time phishing and maliciousness detection tool embedded directly into the Gmail UI. When a user opens an email, the add-on extracts its content, scores it across four independent threat analyzers, and renders a color-coded risk report in the Gmail side panel — all within seconds.

---

## 🚀 Key Features

- **Modular scoring engine** — four independent analyzers (Identity, Content, Link, Infrastructure) each contribute a bounded score. New analyzers can be added without modifying existing logic.
- **Composite risk score** — results are aggregated into a single 0–100 score with a human-readable verdict, color-coded by severity (green / orange / red).
- **Client-side safety layer** — the Gmail frontend truncates email bodies before transmission, acting as a DoS buffer in front of the backend.

---

## 🏗️ Architecture & Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  Gmail (Browser)                                                │
│                                                                 │
│  1. User opens email                                            │
│       │                                                         │
│       ▼                                                         │
│  onGmailMessageOpen(e)                                          │
│    • e.gmail.accessToken  — single-use current-message token    │
│    • GmailApp.getMessageById()                                  │
│    • Extract: sender, subject, body_text, body_html, auth hdr   │
│    • Truncate bodies to 45,000 chars                            │
│    • CacheService.put(messageId → payload, TTL 5 min)           │
│    • Return: initial card with "Analyze Email" button           │
│       │                                                         │
│  2. User clicks "Analyze Email"                                 │
│       │                                                         │
│       ▼                                                         │
│  analyzeCurrentEmail(e)  ← action callback                      │
│    • CacheService.get(messageId)  — no Gmail token needed       │
│    • POST /analyze  →  FastAPI backend (via ngrok tunnel)       │
│    • Render result card                                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                    HTTPS / ngrok tunnel
                              │
┌─────────────────────────────────────────────────────────────────┐
│  FastAPI Backend                                                │
│                                                                 │
│  POST /analyze                                                  │
│    • Pydantic validates & sanitizes EmailPayload                │
│    • EmailThreatScoringService orchestrates 4 analyzers:        │
│        IdentityAnalyzer      (max 30 pts)                       │
│        ContentAnalyzer       (max 25 pts)                       │
│        LinkAnalyzer          (max 25 pts)                       │
│        InfrastructureAnalyzer(max 20 pts)                       │
│    • Applies Multi-Vector Synergy multiplier if >=3 trigger     │
│    • Scores aggregated, capped at 100                           │
│    • Returns: { "score": int, "verdict": str }                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🧠 Architecture Decisions & Trade-offs

**1. Contextual Precision over Recall**
* **Decision:** Strict heuristics often penalize legitimate corporate receipts. We implemented "Neutral Transaction Logic" (ignoring financial keywords if no threats exist) and Brand-Domain Whitelisting to suppress false alarms on trusted senders.
* **Trade-off:** We intentionally sacrifice maximum heuristic sensitivity (Recall) to prioritize high accuracy (Precision). This significantly reduces "noise" on legitimate emails and builds user trust, at the slight risk of missing extremely subtle scams.

**2. Multi-Vector Synergy Scoring**
* **Decision:** We realized that if an email triggered 3 different analyzers with only "medium" scores, the linear sum wasn't high enough to properly alert the user. Because multiple independent threat vectors waking up is inherently suspicious, we implemented a Synergy Multiplier to dynamically boost the final score.
* **Trade-off:** This allows us to keep the maximum penalty of each individual module strictly bounded, but requires careful threshold tuning to ensure the multiplier doesn't over-inflate borderline cases.

**3. Client-Side Buffering**
* **Decision:** To bypass Apps Script's 500-character parameter limit, payloads are serialized into `CacheService` with a 5-minute TTL. Before caching, the client explicitly truncates email bodies to 45,000 characters.
* **Trade-off:** This decoupled state management cleanly protects the FastAPI backend from memory-exhaustion DoS attacks (acting as a pre-buffer), at the minor risk of losing threat signals buried at the very end of abnormally large emails.

**4. Zero-Trust Input Validation**
* **Decision:** We operate on a strict "Zero Trust" policy for any data hitting the FastAPI backend. We assume all incoming payloads from the client could be malicious, malformed, or tampered with. We utilize strict Pydantic models to enforce type safety, sanitize strings, and apply hard character limits (e.g., 50,000 chars) before the payload ever reaches the analysis engine.
* **Trade-off:** While this rigid boundary validation might occasionally reject poorly encoded but legitimate emails (returning a 422 Unprocessable Entity error), it is a necessary compromise to ensure the scoring engine is immune to injection attacks and payload tampering.

---

## 🛠️ Tech Stack

 - **Backend framework : Python 3.10+, FastAPI -** A modern, high-performance backend framework used to build the threat analysis API, offering asynchronous request handling and built-in data validation.
 - **Frontend runtime : Google Apps Script -** The only supported scripting environment for Gmail Add-ons.
 - **Local tunneling : ngrok -** A secure tunneling tool that exposes the local development server to the internet, allowing the Google Apps Script frontend to communicate with the FastAPI backend in real-time.

---

## 💻 Getting Started — Local Setup

### Prerequisites

- Python 3.10+
- [ngrok](https://ngrok.com/) account (free tier)
- personal Gmail account

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the FastAPI server

```bash
uvicorn app.main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`. Verify it is running:

```bash
curl http://localhost:8000/docs
```

### 3. Expose the server via ngrok

```bash
ngrok http 8000
```

Copy the generated HTTPS forwarding URL (e.g., `https://xxxx-xxxx.ngrok-free.dev`).

### 4. Update the frontend URL

In `gmail-addon/Code.gs`, replace the `ANALYZE_URL` constant:

```javascript
const ANALYZE_URL = 'https://YOUR-NGROK-SUBDOMAIN.ngrok-free.dev/analyze';
```

In `gmail-addon/appsscript.json`, update the `urlFetchWhitelist` entry to match:

```json
"urlFetchWhitelist": [
  "https://YOUR-NGROK-SUBDOMAIN.ngrok-free.dev/"
]
```

---

## 📧 Google Apps Script Deployment

### 1. Create a new Apps Script project

Go to [script.google.com](https://script.google.com), click **New project**.

### 2. Paste the source files

- Replace the default `Code.gs` content with the contents of `gmail-addon/Code.gs`.
- Open **Project Settings** → enable **"Show appsscript.json manifest file in editor"**.
- Replace the contents of `appsscript.json` with `gmail-addon/appsscript.json`.

### 3. Authorize the external_request scope

Select `forceScopeAuthorization` in the function dropdown and click **Run (▶)**. Accept the permissions popup. This step only needs to be done once.

### 4. Install the test deployment

**Deploy → Test deployments → Type: Gmail Add-on → Click Install → Click Done**

---

## ▶️ Using the Add-on

1. Open Gmail.
2. Click on any email to open it.
3. The **Threat Scanner** panel appears automatically in the right sidebar, showing the sender and subject.
4. Click **Analyze Email**.
5. Within a few seconds the panel updates with:
   - A color-coded **threat score** (0–100).
   - A **verdict** summarizing the risk level.
   - A per-analyzer breakdown showing which signals contributed to the score.

> **Green** = low risk · **Orange** = suspicious · **Red** = high risk — treat with caution.

---

## 🗺️ Future Roadmap

* **Persistent Intelligence Database:** Implementing a central DB to store and share malicious domains, suspicious links, and known threats.
* **Advanced Link & Attachment Analysis:** Adding URL unshortening (e.g., bit.ly) and metadata scanning for attached PDF/Office files.
* **LLM Integration:** Utilizing a local LLM to analyze semantic context and detect sophisticated attacks.