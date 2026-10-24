/**
 * PhishGuard AI Suite - Multi-Vector Threat Intelligence Dashboard
 * Manages URL Scanner, Email Phishing Analyzer, Live SSL/DNS Inspector, & Quishing QR Detector
 */

let lastAnalysisData = null;
let currentQrFile = null;
const SESSION_HISTORY_KEY = 'phishguard_scan_history_v2';

document.addEventListener('DOMContentLoaded', () => {
    initApp();
});

function initApp() {
    checkBackendHealth();
    loadModelMetrics();
    renderSessionHistory();
    setupEventListeners();
}

function setupEventListeners() {
    // Enter key for URL scanner input
    const urlInput = document.getElementById('targetUrlInput');
    if (urlInput) {
        urlInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                startScan();
            }
        });
    }

    // Drag and drop for QR dropzone
    const dropZone = document.getElementById('qrDropZone');
    if (dropZone) {
        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.style.borderColor = 'var(--neon-cyan)';
                dropZone.style.background = 'rgba(0, 240, 255, 0.08)';
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.style.borderColor = 'rgba(0, 240, 255, 0.35)';
                dropZone.style.background = 'rgba(8, 12, 22, 0.6)';
            });
        });

        dropZone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files && files.length > 0) {
                handleQrFile(files[0]);
            }
        });
    }
}

// -------------------------------------------------------------
// Suite Tab Navigation
// -------------------------------------------------------------
function switchSuiteTab(tabKey) {
    const tabs = {
        'url': { btn: 'tabBtnUrl', panel: 'panelUrlScanner' },
        'email': { btn: 'tabBtnEmail', panel: 'panelEmailAnalyzer' },
        'ssl': { btn: 'tabBtnSsl', panel: 'panelSslDnsInspector' },
        'qr': { btn: 'tabBtnQr', panel: 'panelQrScanner' }
    };

    Object.keys(tabs).forEach(k => {
        const btn = document.getElementById(tabs[k].btn);
        const panel = document.getElementById(tabs[k].panel);
        if (btn && panel) {
            if (k === tabKey) {
                btn.classList.add('active');
                panel.classList.remove('hidden');
                panel.classList.add('active');
            } else {
                btn.classList.remove('active');
                panel.classList.remove('active');
                panel.classList.add('hidden');
            }
        }
    });
}

// -------------------------------------------------------------
// Telemetry & Health Checks
// -------------------------------------------------------------
async function checkBackendHealth() {
    const dot = document.getElementById('systemDot');
    const text = document.getElementById('systemStatusText');

    try {
        const res = await fetch('/health');
        if (res.ok) {
            const data = await res.json();
            if (data.model_loaded) {
                dot.style.background = '#10b981';
                dot.style.boxShadow = '0 0 10px #10b981';
                text.textContent = 'CORE ONLINE • RANDOM FOREST READY';
            } else {
                dot.style.background = '#f59e0b';
                text.textContent = 'SYSTEM WARNING • MODEL UNLOADED';
            }
        }
    } catch (err) {
        dot.style.background = '#ef4444';
        dot.style.boxShadow = '0 0 10px #ef4444';
        text.textContent = 'BACKEND OFFLINE • CONNECT FLASK';
    }
}

async function loadModelMetrics() {
    try {
        const res = await fetch('/api/metrics');
        if (!res.ok) return;
        const data = await res.json();

        if (data.success && data.metrics) {
            const m = data.metrics;
            document.getElementById('statAccuracy').textContent = `${(m.accuracy * 100).toFixed(2)}%`;
            document.getElementById('statPrecision').textContent = `${(m.precision * 100).toFixed(2)}%`;
            document.getElementById('statRecall').textContent = `${(m.recall * 100).toFixed(2)}%`;
            document.getElementById('statF1').textContent = `${(m.f1_score * 100).toFixed(2)}%`;

            if (m.confusion_matrix && m.confusion_matrix.length === 2) {
                document.getElementById('matTN').querySelector('.cell-num').textContent = m.confusion_matrix[0][0].toLocaleString();
                document.getElementById('matFP').querySelector('.cell-num').textContent = m.confusion_matrix[0][1].toLocaleString();
                document.getElementById('matFN').querySelector('.cell-num').textContent = m.confusion_matrix[1][0].toLocaleString();
                document.getElementById('matTP').querySelector('.cell-num').textContent = m.confusion_matrix[1][1].toLocaleString();
            }

            if (m.engine) {
                document.getElementById('statEngineBadge').textContent = m.engine;
            }
        }
    } catch (err) {
        console.warn('Could not auto-fetch metrics:', err);
    }
}

// -------------------------------------------------------------
// TAB 1: URL Scanner Controller
// -------------------------------------------------------------
function selectDemo(url) {
    const input = document.getElementById('targetUrlInput');
    input.value = url;
    input.focus();
    startScan();
}

function clearInput() {
    const input = document.getElementById('targetUrlInput');
    input.value = '';
    input.focus();
}

async function pasteClipboard() {
    try {
        const text = await navigator.clipboard.readText();
        if (text) {
            const input = document.getElementById('targetUrlInput');
            input.value = text.trim();
            input.focus();
        }
    } catch (err) {
        console.warn('Clipboard read failed:', err);
    }
}

function scrollToMetrics() {
    const target = document.getElementById('modelTelemetrySection');
    if (target) {
        target.scrollIntoView({ behavior: 'smooth' });
    }
}

async function startScan() {
    const input = document.getElementById('targetUrlInput');
    const rawUrl = input.value.trim();

    const errorToast = document.getElementById('errorToast');
    const errorMsg = document.getElementById('errorMessageSpan');
    const terminal = document.getElementById('scannerTerminal');
    const report = document.getElementById('reportContainer');
    const scanBtn = document.getElementById('submitScanBtn');

    errorToast.classList.add('hidden');
    report.classList.add('hidden');

    if (!rawUrl) {
        errorMsg.textContent = 'Please enter a target URL or domain to inspect.';
        errorToast.classList.remove('hidden');
        return;
    }

    terminal.classList.remove('hidden');
    scanBtn.disabled = true;
    scanBtn.style.opacity = '0.6';

    try {
        const response = await fetch('/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: rawUrl })
        });

        if (!response.ok) {
            const errJson = await response.json().catch(() => ({}));
            throw new Error(errJson.error || 'Server error occurred during URL inspection.');
        }

        const data = await response.json();
        if (!data.success) throw new Error(data.error || 'Inspection failed.');

        lastAnalysisData = data;

        setTimeout(() => {
            terminal.classList.add('hidden');
            scanBtn.disabled = false;
            scanBtn.style.opacity = '1';
            renderThreatReport(data);
            saveToSessionHistory(data);
        }, 550);

    } catch (err) {
        terminal.classList.add('hidden');
        scanBtn.disabled = false;
        scanBtn.style.opacity = '1';
        errorMsg.textContent = err.message || 'Unable to communicate with detection backend.';
        errorToast.classList.remove('hidden');
    }
}

function renderThreatReport(data) {
    const reportZone = document.getElementById('reportContainer');
    const banner = document.getElementById('verdictBanner');
    const iconHull = document.getElementById('verdictIconHull');
    const kicker = document.getElementById('statusKicker');
    const heading = document.getElementById('verdictHeading');
    const narrative = document.getElementById('verdictNarrative');
    const inspectedUrl = document.getElementById('inspectedUrlVal');

    const gaugeCircle = document.getElementById('gaugeCircle');
    const gaugeScoreNum = document.getElementById('gaugeScoreNum');
    const riskLevelBadge = document.getElementById('riskLevelBadge');
    const gaugeCaption = document.getElementById('gaugeCaption');

    const confidenceNum = document.getElementById('confidenceNum');
    const confidenceBar = document.getElementById('confidenceBar');
    const classLabelNum = document.getElementById('classLabelNum');
    const classLabelSub = document.getElementById('classLabelSub');

    const isPhish = data.verdict === 'phishing';
    inspectedUrl.textContent = data.url;

    banner.classList.remove('safe-mode', 'danger-mode');

    if (isPhish) {
        banner.classList.add('danger-mode');
        kicker.textContent = 'CRITICAL SECURITY THREAT DETECTED';
        heading.textContent = 'POTENTIAL PHISHING ATTACK';
        narrative.textContent = data.explanation || 'Suspicious lexical tokens detected. High likelihood of credential theft or domain spoofing.';

        iconHull.innerHTML = `
            <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
        `;

        riskLevelBadge.textContent = 'HIGH RISK';
        riskLevelBadge.className = 't-badge high';
        gaugeCaption.textContent = 'Malicious indicators detected';
        gaugeCircle.style.stroke = '#ff2a5f';

        classLabelNum.textContent = 'Phishing (Class 0)';
        classLabelNum.style.color = '#ff2a5f';
        classLabelSub.textContent = 'Mapped to PhiUSIIL Malicious Class';
    } else {
        banner.classList.add('safe-mode');
        kicker.textContent = 'SECURITY VERDICT VERIFIED';
        heading.textContent = 'URL LOOKS LEGITIMATE';
        narrative.textContent = data.explanation || 'Lexical structure conforms to standard benign internet domains.';

        iconHull.innerHTML = `
            <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="m9 12 2 2 4-4"/>
            </svg>
        `;

        riskLevelBadge.textContent = 'LOW RISK';
        riskLevelBadge.className = 't-badge low';
        gaugeCaption.textContent = 'Safe browsing profile verified';
        gaugeCircle.style.stroke = '#10b981';

        classLabelNum.textContent = 'Legitimate (Class 1)';
        classLabelNum.style.color = '#10b981';
        classLabelSub.textContent = 'Mapped to PhiUSIIL Benign Class';
    }

    const risk = Number(data.risk_score) || 0;
    const circumference = 301.6;
    const offset = circumference - (circumference * (risk / 100));
    gaugeCircle.style.strokeDashoffset = offset;
    animateCounter(gaugeScoreNum, risk);

    const conf = Number(data.confidence) || 0;
    confidenceNum.textContent = `${conf.toFixed(1)}%`;
    confidenceBar.style.width = `${Math.min(100, Math.max(0, conf))}%`;

    renderCategorizedFeatures(data.features || {});

    reportZone.classList.remove('hidden');
    reportZone.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function animateCounter(elem, targetVal) {
    let start = 0;
    const duration = 650;
    const startTime = performance.now();

    function update(time) {
        const elapsed = time - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const current = (progress * targetVal).toFixed(1);
        elem.textContent = current;

        if (progress < 1) {
            requestAnimationFrame(update);
        } else {
            elem.textContent = targetVal.toFixed(1);
        }
    }
    requestAnimationFrame(update);
}

function renderCategorizedFeatures(feats) {
    const domainBox = document.getElementById('catDomainRows');
    const lexicalBox = document.getElementById('catLexicalRows');
    const obfBox = document.getElementById('catObfRows');

    domainBox.innerHTML = '';
    lexicalBox.innerHTML = '';
    obfBox.innerHTML = '';

    const domainDef = [
        { key: 'DomainLength', label: 'Domain Host Length', alertIf: (v) => v > 35 },
        { key: 'URLLength', label: 'Overall URL Length', alertIf: (v) => v > 75 },
        { key: 'IsDomainIP', label: 'Domain Is Raw IP Address', alertIf: (v) => v === 1, format: (v) => v === 1 ? 'Yes (Anomaly)' : 'No (Hostname)' },
        { key: 'NoOfSubDomain', label: 'Subdomains Beyond Apex', alertIf: (v) => v > 2 }
    ];

    const lexicalDef = [
        { key: 'NoOfLettersInURL', label: 'Alphabetic Characters', alertIf: () => false },
        { key: 'LetterRatioInURL', label: 'Letter Ratio in URL', alertIf: (v) => v < 0.3 || v > 0.85, format: (v) => Number(v).toFixed(3) },
        { key: 'NoOfDegitsInURL', label: 'Numeric Digits Count', alertIf: (v) => v > 8 },
        { key: 'DegitRatioInURL', label: 'Digit Ratio in URL', alertIf: (v) => v > 0.15, format: (v) => Number(v).toFixed(3) },
        { key: 'NoOfEqualsInURL', label: 'Equals Delimiters (=)', alertIf: (v) => v > 3 },
        { key: 'NoOfQMarkInURL', label: 'Question Marks (?)', alertIf: (v) => v > 1 },
        { key: 'NoOfAmpersandInURL', label: 'Ampersands (&)', alertIf: (v) => v > 3 },
        { key: 'NoOfOtherSpecialCharsInURL', label: 'Other Special Chars', alertIf: (v) => v > 3 },
        { key: 'SpacialCharRatioInURL', label: 'Special Character Ratio', alertIf: (v) => v > 0.12, format: (v) => Number(v).toFixed(3) }
    ];

    const obfDef = [
        { key: 'IsHTTPS', label: 'HTTPS Protocol Secure', alertIf: (v) => v === 0, format: (v) => v === 1 ? 'Yes (TLS)' : 'No (Insecure HTTP)' },
        { key: 'HasObfuscation', label: 'Obfuscation Flag (@, %, //)', alertIf: (v) => v === 1, format: (v) => v === 1 ? 'Detected' : 'None' },
        { key: 'NoOfObfuscatedChar', label: 'Obfuscated Char Count', alertIf: (v) => v > 0 },
        { key: 'ObfuscationRatio', label: 'Obfuscation Ratio', alertIf: (v) => v > 0.02, format: (v) => Number(v).toFixed(3) }
    ];

    appendFeatureRows(domainBox, domainDef, feats);
    appendFeatureRows(lexicalBox, lexicalDef, feats);
    appendFeatureRows(obfBox, obfDef, feats);
}

function appendFeatureRows(container, definitions, feats) {
    definitions.forEach(def => {
        if (def.key in feats) {
            const rawVal = feats[def.key];
            const isFlag = def.alertIf ? def.alertIf(rawVal) : false;
            const displayVal = def.format ? def.format(rawVal) : rawVal;

            const row = document.createElement('div');
            row.className = `feat-item ${isFlag ? 'alert' : ''}`;
            row.innerHTML = `
                <div class="feat-meta">
                    <span class="feat-label">${def.label}</span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span class="feat-num">${displayVal}</span>
                    <span class="feat-badge-state ${isFlag ? 'flag' : 'clean'}">${isFlag ? 'FLAG' : 'PASS'}</span>
                </div>
            `;
            container.appendChild(row);
        }
    });
}

function saveToSessionHistory(data) {
    let history = [];
    try {
        const stored = sessionStorage.getItem(SESSION_HISTORY_KEY);
        if (stored) history = JSON.parse(stored);
    } catch (e) { history = []; }

    const item = {
        url: data.url,
        verdict: data.verdict,
        risk_score: data.risk_score,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    };

    history = [item, ...history.filter(h => h.url !== item.url)].slice(0, 6);
    try { sessionStorage.setItem(SESSION_HISTORY_KEY, JSON.stringify(history)); } catch (e) {}
    renderSessionHistory();
}

function renderSessionHistory() {
    const listElem = document.getElementById('historyList');
    if (!listElem) return;
    let history = [];

    try {
        const stored = sessionStorage.getItem(SESSION_HISTORY_KEY);
        if (stored) history = JSON.parse(stored);
    } catch (e) { history = []; }

    if (!history || history.length === 0) {
        listElem.innerHTML = `<div class="empty-history">No URLs scanned during this session yet. Run a scan above to start logging.</div>`;
        return;
    }

    listElem.innerHTML = '';
    history.forEach(item => {
        const isPhish = item.verdict === 'phishing';
        const row = document.createElement('div');
        row.className = 'history-row';
        row.innerHTML = `
            <div class="h-target-info">
                <span class="h-status-dot" style="background: ${isPhish ? '#ff2a5f' : '#10b981'}; box-shadow: 0 0 8px ${isPhish ? '#ff2a5f' : '#10b981'}"></span>
                <div>
                    <div class="h-url-text">${item.url}</div>
                    <div class="h-time-text">${item.time} • ${isPhish ? 'Phishing Detected' : 'Verified Legitimate'}</div>
                </div>
            </div>
            <div class="h-actions">
                <span class="h-risk-score ${isPhish ? 'threat' : 'safe'}">${item.risk_score}% Risk</span>
                <button class="h-rescan-btn" onclick="switchSuiteTab('url'); selectDemo('${item.url}')">Re-scan</button>
            </div>
        `;
        listElem.appendChild(row);
    });
}

function clearScanHistory() {
    sessionStorage.removeItem(SESSION_HISTORY_KEY);
    renderSessionHistory();
}

function copyAnalyzedUrl() {
    if (!lastAnalysisData || !lastAnalysisData.url) return;
    navigator.clipboard.writeText(lastAnalysisData.url).then(() => {
        alert('Analyzed URL copied to clipboard!');
    }).catch(() => {});
}

function exportJsonReport() {
    if (!lastAnalysisData) {
        alert('Please run a URL analysis first.');
        return;
    }
    const reportStr = JSON.stringify(lastAnalysisData, null, 2);
    const blob = new Blob([reportStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard_threat_report_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// -------------------------------------------------------------
// TAB 2: Email & SMS Phishing Analyzer Controller
// -------------------------------------------------------------
const EMAIL_SAMPLES = {
    kyc_scam: "URGENT: Your SBI bank account has been suspended due to pending KYC update. Click http://secure-login.paypal.account-verify.com/login?id=999&auth=fail to verify your identity within 24 hours. Failure will lead to permanent deactivation and legal action.",
    lottery_crypto: "CONGRATULATIONS! You have won a Bitcoin cash prize of 2.5 BTC in our annual international reward lottery! Claim your unclaimed funds immediately at http://www.teramill.com before your bonus expires.",
    password_reset: "CRITICAL ALERT: Unauthorized access detected on your system from an unknown device. Reset your IT support password immediately: http://192.168.1.1/admin-login. Immediate response required.",
    clean_invite: "Hi team, please find attached the agenda for tomorrow's applied cryptography review meeting. You can check the documentation at https://github.com or visit the university portal at https://www.uni-mainz.de."
};

function loadEmailSample(key) {
    const input = document.getElementById('emailTextInput');
    if (input && EMAIL_SAMPLES[key]) {
        input.value = EMAIL_SAMPLES[key];
        analyzeEmailMessage();
    }
}

async function analyzeEmailMessage() {
    const input = document.getElementById('emailTextInput');
    const text = input ? input.value.trim() : '';

    if (!text) {
        alert('Please paste message or email body to analyze.');
        return;
    }

    const btn = document.getElementById('btnAnalyzeMessage');
    btn.disabled = true;
    btn.style.opacity = '0.6';

    try {
        const res = await fetch('/api/analyze-message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        });

        const data = await res.json();
        if (!data.success) throw new Error(data.error || 'Message analysis failed.');

        renderEmailReport(data);

    } catch (err) {
        alert(err.message || 'Error communicating with message analyzer.');
    } finally {
        btn.disabled = false;
        btn.style.opacity = '1';
    }
}

function renderEmailReport(data) {
    const reportZone = document.getElementById('emailResultSection');
    const banner = document.getElementById('emailVerdictBanner');
    const iconHull = document.getElementById('emailIconHull');
    const kicker = document.getElementById('emailStatusKicker');
    const heading = document.getElementById('emailVerdictHeading');
    const narrative = document.getElementById('emailNarrative');

    const scoreNum = document.getElementById('emailOverallScore');
    const badge = document.getElementById('emailThreatBadge');
    const seScore = document.getElementById('emailSeScore');
    const triggersCount = document.getElementById('emailSeTriggersCount');
    const linksStats = document.getElementById('emailLinksStats');
    const malLinksSub = document.getElementById('emailMaliciousLinksSub');

    const triggersList = document.getElementById('emailTriggersList');
    const linksList = document.getElementById('emailLinksList');

    banner.classList.remove('safe-mode', 'danger-mode');

    const isThreat = data.verdict_status === 'threat';
    const isWarning = data.verdict_status === 'warning';

    if (isThreat || isWarning) {
        banner.classList.add('danger-mode');
        kicker.textContent = isThreat ? 'CRITICAL SOCIAL ENGINEERING THREAT' : 'SUSPICIOUS MESSAGE COERCION DETECTED';
        heading.textContent = data.overall_verdict;
        narrative.textContent = data.summary;
        badge.className = 't-badge high';
        badge.textContent = isThreat ? 'HIGH THREAT' : 'SUSPICIOUS';
        scoreNum.style.color = '#ff2a5f';

        iconHull.innerHTML = `
            <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
        `;
    } else {
        banner.classList.add('safe-mode');
        kicker.textContent = 'MESSAGE SAFETY VERIFIED';
        heading.textContent = data.overall_verdict;
        narrative.textContent = data.summary;
        badge.className = 't-badge low';
        badge.textContent = 'SAFE';
        scoreNum.style.color = '#10b981';

        iconHull.innerHTML = `
            <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="m9 12 2 2 4-4"/>
            </svg>
        `;
    }

    scoreNum.textContent = `${data.overall_threat_score}%`;
    seScore.textContent = `${data.social_engineering.score}%`;
    triggersCount.textContent = `${data.social_engineering.total_triggers} coercion keywords flagged`;
    linksStats.textContent = `${data.links_count} Links`;
    malLinksSub.textContent = `${data.malicious_links_count} flagged as malicious links`;

    // Render Trigger Pills
    triggersList.innerHTML = '';
    const triggers = data.social_engineering.triggers || [];
    if (triggers.length === 0) {
        triggersList.innerHTML = `<div class="empty-history" style="padding:10px;">No suspicious social engineering triggers detected.</div>`;
    } else {
        triggers.forEach(t => {
            const item = document.createElement('div');
            item.className = 'feat-item alert';
            item.innerHTML = `
                <div class="feat-meta"><span class="feat-label">Category: ${t.category.toUpperCase()}</span></div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span class="feat-num" style="color:#fda4af;">"${t.term}"</span>
                    <span class="feat-badge-state flag">TRIGGER</span>
                </div>
            `;
            triggersList.appendChild(item);
        });
    }

    // Render Links List
    linksList.innerHTML = '';
    const links = data.embedded_links || [];
    if (links.length === 0) {
        linksList.innerHTML = `<div class="empty-history" style="padding:10px;">No embedded URLs found in the message body.</div>`;
    } else {
        links.forEach(l => {
            const isPhish = l.verdict === 'phishing';
            const item = document.createElement('div');
            item.className = `feat-item ${isPhish ? 'alert' : ''}`;
            item.innerHTML = `
                <div class="feat-meta">
                    <span class="feat-label" style="max-width:250px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${l.original_url}</span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span class="feat-num" style="color:${isPhish ? '#ff2a5f' : '#10b981'};">${l.risk_score}% Risk</span>
                    <span class="feat-badge-state ${isPhish ? 'flag' : 'clean'}">${isPhish ? 'PHISH' : 'LEGIT'}</span>
                </div>
            `;
            linksList.appendChild(item);
        });
    }

    reportZone.classList.remove('hidden');
    reportZone.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// -------------------------------------------------------------
// TAB 3: Live SSL/DNS Inspector Controller
// -------------------------------------------------------------
function loadSslSample(target) {
    const input = document.getElementById('sslTargetInput');
    if (input) {
        input.value = target;
        inspectSslDns();
    }
}

async function inspectSslDns() {
    const input = document.getElementById('sslTargetInput');
    const url = input ? input.value.trim() : '';

    if (!url) {
        alert('Please enter a target domain or URL to inspect.');
        return;
    }

    const btn = document.getElementById('btnInspectSsl');
    btn.disabled = true;
    btn.style.opacity = '0.6';

    try {
        const res = await fetch('/api/inspect-ssl-dns', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        const data = await res.json();
        if (!data.success) throw new Error(data.error || 'SSL/DNS inspection failed.');

        renderSslReport(data);

    } catch (err) {
        alert(err.message || 'Error during cryptographic handshake.');
    } finally {
        btn.disabled = false;
        btn.style.opacity = '1';
    }
}

function renderSslReport(data) {
    const reportZone = document.getElementById('sslResultSection');
    const banner = document.getElementById('sslVerdictBanner');
    const gradeHull = document.getElementById('sslGradeHull');
    const kicker = document.getElementById('sslKicker');
    const heading = document.getElementById('sslHeading');
    const narrative = document.getElementById('sslNarrative');
    const targetHost = document.getElementById('sslTargetHostVal');

    const certRows = document.getElementById('sslCertRows');
    const dnsRows = document.getElementById('sslDnsRows');
    const flagsList = document.getElementById('sslFlagsList');

    banner.classList.remove('safe-mode', 'danger-mode');
    gradeHull.className = 'grade-hull';

    const grade = data.grade || 'F';
    gradeHull.textContent = grade;
    targetHost.textContent = data.target.hostname;

    if (grade === 'A+' || grade === 'A') {
        banner.classList.add('safe-mode');
        gradeHull.classList.add(grade === 'A+' ? 'grade-aplus' : 'grade-a');
        kicker.textContent = 'CRYPTOGRAPHIC TRANSPORT VERIFIED';
        heading.textContent = `CRYPTOGRAPHIC SECURITY GRADE: ${grade}`;
        narrative.textContent = 'Target host employs modern, trusted TLS ciphers with verified Certificate Authority.';
    } else if (grade === 'B' || grade === 'C') {
        gradeHull.classList.add(grade === 'B' ? 'grade-b' : 'grade-c');
        kicker.textContent = 'CRYPTOGRAPHIC WARNING';
        heading.textContent = `CRYPTOGRAPHIC SECURITY GRADE: ${grade}`;
        narrative.textContent = 'Moderate security configuration: host has minor certificate flags or short-lived DV credentials.';
    } else {
        banner.classList.add('danger-mode');
        gradeHull.classList.add('grade-f');
        kicker.textContent = 'CRYPTOGRAPHIC VULNERABILITY / INSECURE';
        heading.textContent = `CRYPTOGRAPHIC SECURITY GRADE: F`;
        narrative.textContent = 'High risk transport: unencrypted HTTP, expired certificate, or host mismatch detected.';
    }

    // Populate Certificate rows
    certRows.innerHTML = '';
    const ssl = data.ssl || {};
    const certItems = [
        { label: 'TLS Protocol Version', val: ssl.protocol_version || 'None (Unencrypted)' },
        { label: 'Negotiated Cipher Suite', val: ssl.cipher_suite || 'N/A' },
        { label: 'Certificate Issuer', val: ssl.issuer?.organization || 'Unknown' },
        { label: 'Common Name (CN)', val: ssl.subject?.common_name || 'N/A' },
        { label: 'Valid Until', val: ssl.valid_to || 'N/A' },
        { label: 'Days Remaining', val: ssl.days_remaining !== null ? `${ssl.days_remaining} days` : 'N/A' },
        { label: 'SAN Match', val: ssl.san_match ? 'Matched Host' : 'Mismatch / No TLS' }
    ];

    certItems.forEach(item => {
        const row = document.createElement('div');
        row.className = 'feat-item';
        row.innerHTML = `
            <div class="feat-meta"><span class="feat-label">${item.label}</span></div>
            <div class="feat-num" style="max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${item.val}</div>
        `;
        certRows.appendChild(row);
    });

    // Populate DNS rows
    dnsRows.innerHTML = '';
    const dns = data.dns || {};
    const dnsItems = [
        { label: 'Resolved IP Addresses', val: (dns.resolved_ips || []).join(', ') || 'Resolution failed' },
        { label: 'IP Architecture', val: dns.ip_version || 'N/A' },
        { label: 'Reverse DNS (PTR)', val: dns.reverse_dns || 'N/A' },
        { label: 'Internal / Bogon Check', val: dns.is_private ? 'Private IP (Warning)' : 'Public Internet Host' },
        { label: 'DNS Resolution Status', val: dns.dns_status || 'Unknown' }
    ];

    dnsItems.forEach(item => {
        const row = document.createElement('div');
        row.className = 'feat-item';
        row.innerHTML = `
            <div class="feat-meta"><span class="feat-label">${item.label}</span></div>
            <div class="feat-num" style="max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${item.val}</div>
        `;
        dnsRows.appendChild(row);
    });

    // Populate Security Flags
    flagsList.innerHTML = '';
    const flags = data.security_flags || [];
    if (flags.length === 0) {
        flagsList.innerHTML = `<div class="empty-history" style="padding:8px; color:var(--safe-emerald);">✓ Zero cryptographic or routing security anomalies detected.</div>`;
    } else {
        flags.forEach(f => {
            const row = document.createElement('div');
            row.className = 'feat-item alert';
            row.innerHTML = `<div class="feat-meta"><span class="feat-label" style="color:#fda4af;">⚠ ${f}</span></div>`;
            flagsList.appendChild(row);
        });
    }

    reportZone.classList.remove('hidden');
    reportZone.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// -------------------------------------------------------------
// TAB 4: Quishing (QR Code) Scanner Controller
// -------------------------------------------------------------
function onQrFileSelected(event) {
    const file = event.target.files[0];
    if (file) handleQrFile(file);
}

function handleQrFile(file) {
    if (!file.type.startsWith('image/')) {
        alert('Please select an image file (PNG, JPG, WebP).');
        return;
    }

    currentQrFile = file;
    const previewWrap = document.getElementById('qrPreviewWrap');
    const previewImg = document.getElementById('qrPreviewImg');
    const fileName = document.getElementById('qrFileName');

    const reader = new FileReader();
    reader.onload = (e) => {
        previewImg.src = e.target.result;
        fileName.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        previewWrap.classList.remove('hidden');
    };
    reader.readAsDataURL(file);
}

async function executeQrScan() {
    if (!currentQrFile) {
        alert('Please select or drop a QR code image first.');
        return;
    }

    const formData = new FormData();
    formData.append('qr_image', currentQrFile);

    try {
        const res = await fetch('/api/scan-qr', {
            method: 'POST',
            body: formData
        });

        const data = await res.json();
        if (!data.success) throw new Error(data.error || 'Failed to decode QR code.');

        renderQrReport(data);

    } catch (err) {
        alert(err.message || 'Error scanning QR code.');
    }
}

function renderQrReport(data) {
    const reportZone = document.getElementById('qrResultSection');
    const banner = document.getElementById('qrVerdictBanner');
    const iconHull = document.getElementById('qrIconHull');
    const kicker = document.getElementById('qrKicker');
    const heading = document.getElementById('qrHeading');
    const narrative = document.getElementById('qrNarrative');
    const payloadVal = document.getElementById('qrDecodedPayload');

    const riskScore = document.getElementById('qrRiskScore');
    const riskBadge = document.getElementById('qrRiskBadge');
    const classLabel = document.getElementById('qrClassLabel');
    const sslGrade = document.getElementById('qrSslGrade');
    const sslIssuer = document.getElementById('qrSslIssuer');

    banner.classList.remove('safe-mode', 'danger-mode');
    payloadVal.textContent = data.payload || 'No payload';

    const isPhish = data.verdict === 'phishing';

    if (isPhish) {
        banner.classList.add('danger-mode');
        kicker.textContent = 'MALICIOUS QUISHING ATTACK DETECTED';
        heading.textContent = 'PHISHING QR CODE FLAGGED';
        narrative.textContent = data.explanation || 'Decoded QR code directs to a high-risk phishing URL designed for deception.';
        riskBadge.className = 't-badge high';
        riskBadge.textContent = 'HIGH RISK';
        riskScore.style.color = '#ff2a5f';

        iconHull.innerHTML = `
            <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
        `;
    } else {
        banner.classList.add('safe-mode');
        kicker.textContent = 'BENIGN QR CODE VERIFIED';
        heading.textContent = 'LEGITIMATE QR CODE';
        narrative.textContent = data.explanation || 'Decoded QR target URL conforms to standard benign internet domains.';
        riskBadge.className = 't-badge low';
        riskBadge.textContent = 'LOW RISK';
        riskScore.style.color = '#10b981';

        iconHull.innerHTML = `
            <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="m9 12 2 2 4-4"/>
            </svg>
        `;
    }

    riskScore.textContent = `${data.risk_score || 0}%`;
    classLabel.textContent = data.prediction || 'Evaluated';

    if (data.ssl_dns) {
        sslGrade.textContent = `Grade ${data.ssl_dns.grade || 'N/A'}`;
        sslIssuer.textContent = `Issuer: ${data.ssl_dns.ssl?.issuer?.organization || 'Unknown'}`;
    } else {
        sslGrade.textContent = 'N/A';
        sslIssuer.textContent = 'Non-web payload';
    }

    reportZone.classList.remove('hidden');
    reportZone.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
