# Threat Scanner — Gmail Add-on Email Analyzer

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
│  onGmailMessageOpen(e)   ← contextual trigger event            │
│    • e.gmail.accessToken  — single-use current-message token   │
│    • GmailApp.getMessageById()                                  │
│    • Extract: sender, subject, body_text, body_html, auth hdr  │
│    • Truncate bodies to 45,000 chars                           │
│    • CacheService.put(messageId → payload, TTL 5 min)          │
│    • Return: initial card with "Analyze Email" button           │
│       │                                                         │
│  2. User clicks "Analyze Email"                                 │
│       │                                                         │
│       ▼                                                         │
│  analyzeCurrentEmail(e)  ← action callback                     │
│    • CacheService.get(messageId)  — no Gmail token needed      │
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
│    • Scores aggregated, capped at 100                           │
│    • Returns: { "score": int, "verdict": str }                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🧠 Design Decisions & Trade-offs

### 1. State Management via CacheService

The Gmail Add-on platform passes data between a contextual trigger and a button-action callback exclusively through `CardService.newAction().setParameters()`, which enforces a **500-character limit** on all values. A serialized email payload (sender, subject, full body, headers) far exceeds this limit.

**Decision:** Extract the full payload inside `onGmailMessageOpen` — where the Gmail message access token is guaranteed to be present — serialize it to JSON, and store it in `CacheService.getUserCache()` under a `messageId` key with a 5-minute TTL. The button callback then reads the payload from cache using only the short `messageId` parameter.

This completely decouples token-dependent Gmail API access (contextual trigger) from network I/O (action callback), and sidesteps the parameter size constraint without any data loss.

### 2. Client-Side Truncation as a Security Buffer

The FastAPI backend enforces a hard 50,000-character limit on `body_text` and `body_html` via Pydantic validators, designed to prevent memory exhaustion from oversized inputs.

**Decision:** The Apps Script frontend truncates both fields to **45,000 characters** before caching the payload. This 5,000-character safety margin ensures that even if serialization overhead, header fields, or encoding differences inflate the transmitted size, the backend validator is never exercised as a first line of defense. The client acts as a lightweight DoS buffer, keeping the backend's Pydantic validation as a secondary enforcement layer rather than the primary gate.

### 3. Modular Analyzer Architecture for Scalability

A monolithic scoring function would require modification every time a new threat signal is added, violating the Open/Closed Principle.

**Decision:** Each threat vector is encapsulated in its own class (`IdentityAnalyzer`, `ContentAnalyzer`, `LinkAnalyzer`, `InfrastructureAnalyzer`) implementing a common `.analyze(payload) → AnalysisModuleResult` interface. The `EmailThreatScoringService` orchestrator iterates over a registered analyzer list, making it trivial to add, remove, or reorder analyzers without touching any other module. Score caps are enforced per-module (`MAX_SCORE`) and the total is capped at 100 by the aggregator.

---

## 🛠️ Tech Stack

 - **Backend framework : Python 3.10+, FastAPI -** A modern, high-performance backend framework used to build the threat analysis API, offering asynchronous request handling and built-in data validation.
 - **Frontend runtime : Google Apps Script -** The only supported scripting environment for Gmail Add-ons. The V8 runtime enables modern JavaScript (const/let, destructuring, arrow functions) and gives direct access to `GmailApp`, `CardService`, `CacheService`, and `UrlFetchApp` — all required by this project.
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

1. Open [Gmail](https://mail.google.com).
2. Click on any email to open it.
3. The **Threat Scanner** panel appears automatically in the right sidebar, showing the sender and subject.
4. Click **Analyze Email**.
5. Within a few seconds the panel updates with:
   - A color-coded **threat score** (0–100).
   - A **verdict** summarizing the risk level.
   - A per-analyzer breakdown showing which signals contributed to the score.

> **Green** = low risk · **Orange** = suspicious · **Red** = high risk — treat with caution.

---"# gmail-threat-scanner" 
