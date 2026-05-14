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
* **Decision:** Strict heuristics often penalize legitimate corporate emails. We replaced static, unscalable whitelists with **Dynamic Identity Alignment** (mathematically matching the sender's display name against the root domain) and implemented "Neutral Transaction Logic" (ignoring financial keywords if no threats exist).
* **Trade-off:** We intentionally sacrifice maximum heuristic sensitivity (Recall) to prioritize high accuracy (Precision) and system scalability. This significantly reduces "noise" on legitimate emails and eliminates the maintenance overhead of hardcoded lists, at the slight risk of missing extremely subtle scams.

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

### 1. Terminal 1 - Install dependencies

Open a terminal and download the project code to your local machine, then navigate into the project folder:

```bash
git clone [https://github.com/lavital11/gmail-threat-scanner.git](https://github.com/lavital11/gmail-threat-scanner.git)
cd gmail-threat-scanner
```
Once inside the project folder, install the required Python packages by running:

```bash
pip install -r requirements.txt
```

### 2. Start the FastAPI server

In the same terminal, start the server by running:

```bash
uvicorn app.main:app --reload --port 8000
```

To verify the server is running, open your web browser and go to http://localhost:8000/docs. You should see the FastAPI documentation page appear.

### 3. Terminal 2 - Expose the server via ngrok
Open a new, separate terminal window and run the following command to expose your local server to the internet:

```bash
ngrok http 8000
```

A screen will appear in your terminal showing the ngrok connection details. Look for the line that says "Forwarding". Copy the full HTTPS URL shown there (e.g., https://xxxx-xxxx.ngrok-free.dev).

### 4. Update the frontend URL

In gmail-addon/Code.gs, replace the ANALYZE_URL constant with the URL you copied, making sure to add /analyze at the end:

```javascript
const ANALYZE_URL = 'https://YOUR-NGROK-SUBDOMAIN.ngrok-free.dev/analyze';
```

In gmail-addon/appsscript.json, update the urlFetchWhitelist entry with the URL you copied, making sure to add a trailing slash /:

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

1. In the Apps Script editor, look at the **top toolbar** (right next to the "Run" and "Debug" buttons).
2. You will see a dropdown menu (it might currently display `analyzeCurrentEmail` or another function name). Click this dropdown and select `forceScopeAuthorization`.
3. Click the **Run (▶)** button.
4. An "Authorization Required" popup will appear. Click **Review Permissions**, select your Google account, then click **Advanced** -> **Go to Threat Scanner (unsafe)** -> **Allow**.

*(Note: This forces Google to grant the necessary permissions for the add-on to send data to your local backend. This step only needs to be done once).*

### 4. Install the test deployment

1. In the top right corner of the editor, click the blue **Deploy** button.
2. Select **Test deployments** from the dropdown menu.
3. Make sure the Application Type is set to **Gmail Add-on** (if not, click the gear/settings icon next to "Select type" and choose it).
4. Click **Install**, and then click **Done**.

## ▶️ Using the Add-on

1. Open Gmail.
2. Click on any email to open it.
3. The **Threat Scanner** panel appears automatically in the sidebar (right or left, depending on your Gmail language), showing the sender and subject.
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