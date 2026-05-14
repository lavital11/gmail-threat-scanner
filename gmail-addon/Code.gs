/**
 * @file Threat Scanner — Gmail Add-on
 * Analyzes the currently open email for phishing and maliciousness indicators
 * by forwarding extracted message fields to a FastAPI scoring backend.
 *
 * Architecture:
 *   The Gmail current-message access token is only available inside a
 *   contextual trigger event. The add-on therefore reads and caches the full
 *   email payload during onGmailMessageOpen, then the button callback
 *   retrieves the cached payload and calls the backend without touching
 *   GmailApp a second time.
 */

const ANALYZE_URL    = 'https://charcoal-contend-spongy.ngrok-free.dev/analyze';
const BODY_MAX_CHARS = 45000;
const CACHE_TTL      = 300; // seconds

/** Maps backend analyzer keys to user-facing breakdown labels (with emoji). */
const ANALYZER_FRIENDLY_NAMES_ = {
  IdentityAnalyzer: '👤 Sender Identity',
  ContentAnalyzer: '📝 Message Content',
  LinkAnalyzer: '🔗 Suspicious Links',
  InfrastructureAnalyzer: '🛡️ Infrastructure Security'
};

// ─── Contextual trigger ───────────────────────────────────────────────────────

/**
 * Entry point fired automatically when the user opens a Gmail message.
 * Extracts message fields, caches the payload for the button callback,
 * and returns the initial card.
 *
 * @param {Object} e  Gmail add-on contextual-trigger event.
 * @returns {Card}
 */
function onGmailMessageOpen(e) {
  try {
    const accessToken = e.gmail.accessToken;
    const messageId   = e.gmail.messageId;

    GmailApp.setCurrentMessageAccessToken(accessToken);
    const message = GmailApp.getMessageById(messageId);

    if (!message) {
      throw new Error('Could not load the requested message.');
    }

    const senderRaw = message.getFrom() || '';
    const subject   = message.getSubject() || '';

    const payload = {
      sender_name:            parseSenderName_(senderRaw),
      sender_email:           parseSenderEmail_(senderRaw),
      subject:                subject,
      body_text:              truncate_(message.getPlainBody() || '', BODY_MAX_CHARS),
      body_html:              truncate_(message.getBody()      || '', BODY_MAX_CHARS),
      authentication_results: safeHeader_(message, 'Authentication-Results')
    };

    CacheService.getUserCache().put(cacheKey_(messageId), JSON.stringify(payload), CACHE_TTL);

    return buildInitialCard_(messageId, subject, payload.sender_name);

  } catch (err) {
    return buildErrorCard_(err);
  }
}

// ─── Initial card ─────────────────────────────────────────────────────────────

/**
 * Builds the welcome card shown on email open.
 * Displays a sender and subject preview with an "Analyze Email" action button.
 *
 * @param {string} messageId
 * @param {string} subject
 * @param {string} senderName
 * @returns {Card}
 */
function buildInitialCard_(messageId, subject, senderName) {
  const action = CardService.newAction()
    .setFunctionName('analyzeCurrentEmail')
    .setParameters({ messageId: messageId });

  const analyzeBtn = CardService.newTextButton()
    .setText('Analyze Email')
    .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
    .setOnClickAction(action);

  const section = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('From')
        .setText(esc_(senderName || '(unknown)'))
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Subject')
        .setText(esc_(truncate_(subject || '(no subject)', 120)))
    )
    .addWidget(CardService.newDivider())
    .addWidget(analyzeBtn);

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Threat Scanner'))
    .addSection(section)
    .build();
}

// ─── Button action callback ───────────────────────────────────────────────────

/**
 * Handles the "Analyze Email" button click.
 * Retrieves the cached payload, posts it to the backend, and replaces
 * the current card with the analysis result.
 *
 * @param {Object} e  Apps Script action event.
 * @returns {ActionResponse}
 */
function analyzeCurrentEmail(e) {
  try {
    const messageId = e.parameters && e.parameters.messageId
      ? e.parameters.messageId : '';

    if (!messageId) {
      throw new Error('Message context unavailable. Please reopen the email.');
    }

    const cached = CacheService.getUserCache().get(cacheKey_(messageId));
    if (!cached) {
      throw new Error('Session expired. Please close and reopen the email.');
    }

    const emailPayload = JSON.parse(cached);
    const { status, body } = postToBackend_(emailPayload);

    console.log('Backend response — status: ' + status + ', body: ' + truncate_(body, 300));

    const result = parseResponse_(status, body);
    return updateCard_(buildResultCard_(result.score, result.verdict));

  } catch (err) {
    return updateCard_(buildErrorCard_(err));
  }
}

// ─── Backend communication ────────────────────────────────────────────────────

/**
 * Posts the email payload to the FastAPI /analyze endpoint.
 *
 * @param {Object} payload  EmailPayload-compatible object.
 * @returns {{status: number, body: string}}
 */
function postToBackend_(payload) {
  let res;
  try {
    res = UrlFetchApp.fetch(ANALYZE_URL, {
      method:             'post',
      contentType:        'application/json',
      payload:            JSON.stringify(payload),
      headers: {
        'ngrok-skip-browser-warning': 'true'
      },
      muteHttpExceptions: true,
      followRedirects:    false
    });
  } catch (netErr) {
    throw new Error('Backend unreachable. Verify the server and tunnel are running.');
  }
  return { status: res.getResponseCode(), body: res.getContentText() || '' };
}

/**
 * Validates the HTTP response and parses the JSON body.
 * Handles proxy-layer double-encoding by applying a second JSON.parse
 * when the first parse yields a string instead of an object.
 *
 * Expected backend contract: { "score": number, "verdict": string }
 *
 * @param {number} status
 * @param {string} body  Raw response text.
 * @returns {{score: number, verdict: string}}
 */
function parseResponse_(status, body) {
  if (status < 200 || status >= 300) {
    throw new Error(
      'Backend returned HTTP ' + status + ': ' +
      truncate_(body.replace(/\s+/g, ' ').trim(), 400)
    );
  }

  let data;
  try {
    data = JSON.parse(body);
  } catch (_) {
    throw new Error('Response body is not valid JSON: ' + truncate_(body, 300));
  }

  // Unwrap double-encoded responses (proxy layers may serialize the JSON twice).
  if (typeof data === 'string') {
    try {
      data = JSON.parse(data);
    } catch (_) {
      throw new Error('Response could not be decoded: ' + truncate_(data, 300));
    }
  }

  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new Error('Unexpected response shape. Received: ' + truncate_(JSON.stringify(data), 200));
  }

  const rawScore = data.score;
  const score = typeof rawScore === 'number'
    ? rawScore
    : (typeof rawScore === 'string' && !isNaN(Number(rawScore)) ? Number(rawScore) : null);

  if (score === null) {
    throw new Error(
      'Response is missing a numeric "score". Keys received: [' +
      Object.keys(data).join(', ') + ']'
    );
  }

  const verdict = typeof data.verdict === 'string' && data.verdict.trim()
    ? data.verdict.trim()
    : '(no verdict returned)';

  return {
    score:   Math.max(0, Math.min(100, Math.floor(score))),
    verdict: verdict
  };
}

// ─── Result card ──────────────────────────────────────────────────────────────

/**
 * Builds the analysis result card.
 *
 * Score is displayed in a DecoratedText widget (topLabel / number / bottomLabel)
 * to prevent RTL reflow from reversing "X out of 100" in Hebrew interfaces.
 *
 * The verdict string is parsed with a regex to extract individual analyzer
 * results and reformatted as a clean list. Each line is prefixed with the
 * Unicode Left-To-Right Mark (&#x200E;) to force LTR rendering — CardService
 * strips HTML dir/align attributes, so this Unicode character is the only
 * reliable way to fix the jumping-period bug in RTL locales.
 *
 * Colour coding:
 *   score >= 70  →  red    (#d93025)
 *   score >= 40  →  orange (#ef6c00)
 *   score <  40  →  green  (#188038)
 *
 * Permitted HTML tags: <b>, <br>, <font>. Analyzer keys are mapped to friendly
 * labels (including emoji) via ANALYZER_FRIENDLY_NAMES_; unknown keys are unchanged.
 *
 * @param {number} score
 * @param {string} verdict  Raw explanation string from the backend.
 * @returns {Card}
 */
function buildResultCard_(score, verdict) {
  const sev = severity_(score);

  // Score widget — three-slot layout prevents RTL number reversal.
  const scoreWidget = CardService.newDecoratedText()
    .setTopLabel('Final Threat Score')
    .setText('<font color="' + sev.color + '"><b>' + score + '</b></font>')
    .setBottomLabel('out of 100');

  // Remove the redundant inline total already shown by the score widget.
  const cleaned = verdict
    .replace(/Total score:\s*\d+\/\d+\.?\s*/gi, '')
    .trim();

  // Split into summary sentence (before the first "[") and module detail.
  const bracketPos = cleaned.indexOf('[');
  const summaryRaw = bracketPos === -1 ? cleaned : cleaned.slice(0, bracketPos).trim();

  const summaryHtml = summaryRaw
    ? '<b>' + esc_(summaryRaw) + '</b><br><br>'
    : '';

  // Parse each "[ModuleName: Score] Explanation" block into a clean line.
  const moduleRegex = /\[(.*?):\s*(\d+)\]\s*(.*?)(?=\[|$)/gs;
  let modulesHtml = '';
  let match;

  while ((match = moduleRegex.exec(cleaned)) !== null) {
    const rawAnalyzerKey = match[1].trim();
    const friendlyLabel = ANALYZER_FRIENDLY_NAMES_[rawAnalyzerKey] || rawAnalyzerKey;
    const moduleName  = esc_(friendlyLabel);
    const moduleScore = esc_(match[2].trim());
    const explanation = esc_(match[3].trim());

    // &#x200E; = Unicode LTR Mark — forces LTR rendering for this line.
    modulesHtml +=
      '<br><br>&#x200E;<b>' + moduleName + ': ' + moduleScore + '</b>' +
      (explanation ? ' - ' + explanation : '');
  }

  const verdictWidget = CardService.newTextParagraph()
    .setText(
      '<font color="' + sev.color + '">' + summaryHtml + modulesHtml + '</font>'
    );

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Analysis Result'))
    .addSection(
      CardService.newCardSection()
        .addWidget(scoreWidget)
        .addWidget(CardService.newDivider())
        .addWidget(verdictWidget)
    )
    .build();
}

// ─── Error card ───────────────────────────────────────────────────────────────

/**
 * Builds a card displaying a user-readable error message.
 * Uses only text widgets — no icons.
 *
 * @param {Error|*} err
 * @returns {Card}
 */
function buildErrorCard_(err) {
  const msg = err && err.message ? err.message : String(err || 'An unexpected error occurred.');

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Threat Scanner'))
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel('Analysis failed')
            .setText('<font color="#d93025"><b>' + esc_(msg) + '</b></font>')
        )
    )
    .build();
}

// ─── Homepage card ────────────────────────────────────────────────────────────

/**
 * Displayed when the add-on panel is opened outside of a message context.
 * Required by the manifest homepageTrigger.
 *
 * @returns {Card}
 */
function buildHomepageCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Threat Scanner'))
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText('Open any email in Gmail to scan it for phishing indicators.')
        )
    )
    .build();
}

// ─── OAuth scope initializer (one-time manual run) ───────────────────────────

/**
 * Triggers the OAuth consent flow for the external_request scope.
 * Run once manually from the Apps Script editor function dropdown,
 * then click "Allow" in the permissions popup.
 * Do not invoke this function from any card or trigger.
 */
function forceScopeAuthorization() {
  UrlFetchApp.fetch(ANALYZE_URL, { method: 'get', muteHttpExceptions: true });
  Logger.log('OAuth scope for external_request confirmed.');
}

// ─── Navigation ───────────────────────────────────────────────────────────────

/**
 * Returns an ActionResponse that replaces the current card with the given card.
 *
 * @param {Card} card
 * @returns {ActionResponse}
 */
function updateCard_(card) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(card))
    .build();
}

// ─── Utilities ────────────────────────────────────────────────────────────────

/**
 * Returns the CacheService key for a given messageId.
 * @param {string} messageId
 * @returns {string}
 */
function cacheKey_(messageId) {
  return 'threat_payload:' + messageId;
}

/**
 * Extracts the display name from a raw From header.
 * Supports "Display Name <email>" and bare "email" formats.
 * @param {string} raw
 * @returns {string}
 */
function parseSenderName_(raw) {
  const m = String(raw || '').trim().match(/^(.*?)\s*<[^>]+>\s*$/);
  return m ? m[1].replace(/^"|"$/g, '').trim() || parseSenderEmail_(raw) : (raw.trim() || 'Unknown');
}

/**
 * Extracts the email address from a raw From header.
 * @param {string} raw
 * @returns {string}
 */
function parseSenderEmail_(raw) {
  const m = String(raw || '').trim().match(/<([^>]+)>/);
  return m ? m[1].trim() : (raw.trim() || 'unknown@example.local');
}

/**
 * Reads a message header safely, returning an empty string if absent.
 * @param {GmailMessage} message
 * @param {string} name
 * @returns {string}
 */
function safeHeader_(message, name) {
  try { return message.getHeader(name) || ''; } catch (_) { return ''; }
}

/**
 * Truncates a string to at most maxLen characters.
 * @param {string} s
 * @param {number} maxLen
 * @returns {string}
 */
function truncate_(s, maxLen) {
  const str = String(s || '');
  return str.length > maxLen ? str.slice(0, maxLen) : str;
}

/**
 * Maps a 0-100 threat score to a severity colour.
 * @param {number} score
 * @returns {{color: string}}
 */
function severity_(score) {
  if (score >= 70) return { color: '#d93025' }; // High   — red
  if (score >= 40) return { color: '#ef6c00' }; // Medium — orange
  return               { color: '#188038' }; // Low    — green
}

/**
 * Escapes HTML special characters for safe embedding in CardService text fields.
 * @param {string} v
 * @returns {string}
 */
function esc_(v) {
  return String(v || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
