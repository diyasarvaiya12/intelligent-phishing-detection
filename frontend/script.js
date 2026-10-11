/**
 * PhishGuard AI 2.0 - Next-Gen Threat Intelligence Dashboard
 * Real-time heuristic scanning & Random Forest inference client
 */

let lastAnalysisData = null;
const SESSION_HISTORY_KEY = 'phishguard_scan_history_v2';

document.addEventListener('DOMContentLoaded', () => {
    initApp();
});

function initApp() {
    checkBackendHealth();
    loadModelMetrics();
    renderSessionHistory();

    // Enable Enter key on input
    const input = document.getElementById('targetUrlInput');
    if (input) {
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                startScan();
            }
        });
    }
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
// Interactive Input Helpers
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

// -------------------------------------------------------------
// Core Scanner Action
// -------------------------------------------------------------
async function startScan() {
    const input = document.getElementById('targetUrlInput');
    const rawUrl = input.value.trim();

    const errorToast = document.getElementById('errorToast');
    const errorMsg = document.getElementById('errorMessageSpan');
    const terminal = document.getElementById('scannerTerminal');
    const report = document.getElementById('reportContainer');
    const scanBtn = document.getElementById('submitScanBtn');

    // Reset banners
    errorToast.classList.add('hidden');
    report.classList.add('hidden');

    if (!rawUrl) {
        errorMsg.textContent = 'Please enter a target URL or domain to inspect.';
        errorToast.classList.remove('hidden');
        return;
    }

    // Launch holographic radar terminal
    terminal.classList.remove('hidden');
    scanBtn.disabled = true;
    scanBtn.style.opacity = '0.6';

    try {
        const response = await fetch('/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: rawUrl })
        });

        if (!response.ok) {
            const errJson = await response.json().catch(() => ({}));
            throw new Error(errJson.error || 'Server error occurred during URL inspection.');
        }

        const data = await response.json();
        if (!data.success) {
            throw new Error(data.error || 'Inspection failed.');
        }

        lastAnalysisData = data;

        // Brief delay to allow radar animation to smoothly display heuristic feedback
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

// -------------------------------------------------------------
// Threat Intelligence Report Rendering
// -------------------------------------------------------------
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

    // Reset modes
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

    // Circular Gauge Animation
    const risk = Number(data.risk_score) || 0;
    const circumference = 301.6;
    const offset = circumference - (circumference * (risk / 100));
    gaugeCircle.style.strokeDashoffset = offset;
    animateCounter(gaugeScoreNum, risk);

    // Confidence
    const conf = Number(data.confidence) || 0;
    confidenceNum.textContent = `${conf.toFixed(1)}%`;
    confidenceBar.style.width = `${Math.min(100, Math.max(0, conf))}%`;

    // Render Categorized 17 Features
    renderCategorizedFeatures(data.features || {});

    // Reveal report with smooth scroll
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

// -------------------------------------------------------------
// Categorized 17 Feature Decomposition
// -------------------------------------------------------------
function renderCategorizedFeatures(feats) {
    const domainBox = document.getElementById('catDomainRows');
    const lexicalBox = document.getElementById('catLexicalRows');
    const obfBox = document.getElementById('catObfRows');

    domainBox.innerHTML = '';
    lexicalBox.innerHTML = '';
    obfBox.innerHTML = '';

    // Category 1: Domain & Host Structure
    const domainDef = [
        { key: 'DomainLength', label: 'Domain Host Length', alertIf: (v) => v > 35 },
        { key: 'URLLength', label: 'Overall URL Length', alertIf: (v) => v > 75 },
        { key: 'IsDomainIP', label: 'Domain Is Raw IP Address', alertIf: (v) => v === 1, format: (v) => v === 1 ? 'Yes (Anomaly)' : 'No (Hostname)' },
        { key: 'NoOfSubDomain', label: 'Subdomains Beyond Apex', alertIf: (v) => v > 2 }
    ];

    // Category 2: Lexical & Character Metrics
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

    // Category 3: Obfuscation & Security Tokens
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

// -------------------------------------------------------------
// Session History Logger
// -------------------------------------------------------------
function saveToSessionHistory(data) {
    let history = [];
    try {
        const stored = sessionStorage.getItem(SESSION_HISTORY_KEY);
        if (stored) history = JSON.parse(stored);
    } catch (e) {
        history = [];
    }

    const item = {
        url: data.url,
        verdict: data.verdict,
        risk_score: data.risk_score,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    };

    // Prepend and limit to 6 recent items
    history = [item, ...history.filter(h => h.url !== item.url)].slice(0, 6);

    try {
        sessionStorage.setItem(SESSION_HISTORY_KEY, JSON.stringify(history));
    } catch (e) {}

    renderSessionHistory();
}

function renderSessionHistory() {
    const listElem = document.getElementById('historyList');
    let history = [];

    try {
        const stored = sessionStorage.getItem(SESSION_HISTORY_KEY);
        if (stored) history = JSON.parse(stored);
    } catch (e) {
        history = [];
    }

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
                <button class="h-rescan-btn" onclick="selectDemo('${item.url}')">Re-scan</button>
            </div>
        `;
        listElem.appendChild(row);
    });
}

function clearScanHistory() {
    sessionStorage.removeItem(SESSION_HISTORY_KEY);
    renderSessionHistory();
}

// -------------------------------------------------------------
// Export & Clipboard Helpers
// -------------------------------------------------------------
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
