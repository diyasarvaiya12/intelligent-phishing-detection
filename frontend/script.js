/**
 * PhishGuard - Frontend Interaction & ML API Integration
 * Communicates with Flask backend (/predict, /api/metrics, /health)
 */

document.addEventListener('DOMContentLoaded', () => {
    loadModelMetrics();
    checkHealth();
});

// Quick demo sample filler
function setSample(url) {
    const input = document.getElementById('urlInput');
    input.value = url;
    input.focus();
}

// Health check to update status badge
async function checkHealth() {
    try {
        const res = await fetch('/health');
        if (res.ok) {
            const data = await res.json();
            const ind = document.getElementById('engineStatusIndicator');
            const txt = document.getElementById('engineStatusText');
            if (data.model_loaded) {
                ind.style.background = '#10b981';
                txt.textContent = 'ML Engine Active (Model Loaded)';
            } else {
                ind.style.background = '#f59e0b';
                txt.textContent = 'ML Engine (Model Not Loaded)';
            }
        }
    } catch (err) {
        const ind = document.getElementById('engineStatusIndicator');
        const txt = document.getElementById('engineStatusText');
        ind.style.background = '#ef4444';
        txt.textContent = 'ML Backend Offline';
    }
}

// Load real evaluation metrics from model training
async function loadModelMetrics() {
    try {
        const res = await fetch('/api/metrics');
        if (!res.ok) return;
        const json = await res.json();
        if (json.success && json.metrics) {
            const m = json.metrics;
            document.getElementById('metricAccuracy').textContent = `${(m.accuracy * 100).toFixed(2)}%`;
            document.getElementById('metricPrecision').textContent = `${(m.precision * 100).toFixed(2)}%`;
            document.getElementById('metricRecall').textContent = `${(m.recall * 100).toFixed(2)}%`;
            document.getElementById('metricF1').textContent = `${(m.f1_score * 100).toFixed(2)}%`;

            if (m.confusion_matrix && m.confusion_matrix.length === 2) {
                document.getElementById('cmTN').textContent = m.confusion_matrix[0][0];
                document.getElementById('cmFP').textContent = m.confusion_matrix[0][1];
                document.getElementById('cmFN').textContent = m.confusion_matrix[1][0];
                document.getElementById('cmTP').textContent = m.confusion_matrix[1][1];
            }

            if (m.engine) {
                document.getElementById('cmEngine').textContent = m.engine;
            }
        }
    } catch (err) {
        console.warn('Could not load metrics automatically:', err);
    }
}

// Scan URL handler
async function scanUrl() {
    const urlInput = document.getElementById('urlInput');
    const rawUrl = urlInput.value.trim();

    const errorBanner = document.getElementById('errorMessage');
    const errorText = document.getElementById('errorText');
    const loadingState = document.getElementById('loadingState');
    const resultSection = document.getElementById('resultSection');
    const scanBtn = document.getElementById('scanBtn');

    // Reset banners
    errorBanner.classList.add('hidden');
    resultSection.classList.add('hidden');

    if (!rawUrl) {
        errorText.textContent = 'Please enter a URL to inspect.';
        errorBanner.classList.remove('hidden');
        return;
    }

    // Activate loading state
    loadingState.classList.remove('hidden');
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
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || 'Unable to analyze URL. Please make sure the ML backend is running.');
        }

        const data = await response.json();

        if (!data.success) {
            throw new Error(data.error || 'Analysis failed.');
        }

        renderResult(data);

    } catch (err) {
        errorText.textContent = err.message || 'Unable to analyze URL. Please make sure the ML backend is running.';
        errorBanner.classList.remove('hidden');
    } finally {
        loadingState.classList.add('hidden');
        scanBtn.disabled = false;
        scanBtn.style.opacity = '1';
    }
}

// Render analysis result
function renderResult(data) {
    const resultCard = document.getElementById('resultCard');
    const verdictTitle = document.getElementById('verdictTitle');
    const verdictExplanation = document.getElementById('verdictExplanation');
    const scannedUrlText = document.getElementById('scannedUrlText');
    const verdictIconWrap = document.getElementById('verdictIconWrap');
    const riskScoreVal = document.getElementById('riskScoreVal');
    const riskBarFill = document.getElementById('riskBarFill');
    const riskBadge = document.getElementById('riskBadge');
    const confidenceVal = document.getElementById('confidenceVal');
    const classificationVal = document.getElementById('classificationVal');
    const labelMappingHint = document.getElementById('labelMappingHint');
    const featuresGrid = document.getElementById('featuresGrid');
    const resultSection = document.getElementById('resultSection');

    // Scanned URL display
    scannedUrlText.textContent = data.url;

    // Reset classes
    resultCard.classList.remove('verdict-safe', 'verdict-danger');
    riskBarFill.classList.remove('safe', 'danger');

    const isPhishing = data.verdict === 'phishing';

    if (isPhishing) {
        resultCard.classList.add('verdict-danger');
        verdictTitle.textContent = 'POTENTIAL PHISHING DETECTED';
        verdictExplanation.textContent = data.explanation || 'Suspicious lexical patterns indicate a high likelihood of a phishing attempt.';
        verdictIconWrap.innerHTML = `
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
        `;
        riskBadge.textContent = 'HIGH RISK';
        riskBadge.className = 'score-badge high';
        riskBarFill.classList.add('danger');
        classificationVal.textContent = 'Phishing (0)';
        classificationVal.style.color = '#ef4444';
        labelMappingHint.textContent = 'Class 0 in PhiUSIIL dataset';
    } else {
        resultCard.classList.add('verdict-safe');
        verdictTitle.textContent = 'URL LOOKS LEGITIMATE';
        verdictExplanation.textContent = data.explanation || 'URL exhibits standard lexical patterns consistent with benign web domains.';
        verdictIconWrap.innerHTML = `
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <polyline points="9 12 11 14 15 10"/>
            </svg>
        `;
        riskBadge.textContent = 'LOW RISK';
        riskBadge.className = 'score-badge low';
        riskBarFill.classList.add('safe');
        classificationVal.textContent = 'Legitimate (1)';
        classificationVal.style.color = '#10b981';
        labelMappingHint.textContent = 'Class 1 in PhiUSIIL dataset';
    }

    // Animate Risk Score & Bar
    const riskScore = data.risk_score || 0;
    riskScoreVal.textContent = `${riskScore}%`;
    riskBarFill.style.width = `${Math.min(100, Math.max(0, riskScore))}%`;

    // Confidence
    confidenceVal.textContent = `${data.confidence || 0}%`;

    // Feature pills mapping with clean human-readable names
    const featureLabels = {
        'URLLength': 'URL Length',
        'DomainLength': 'Domain Length',
        'IsDomainIP': 'Is Domain IP Address',
        'NoOfSubDomain': 'Number of Subdomains',
        'HasObfuscation': 'Obfuscation Detected',
        'NoOfObfuscatedChar': 'Obfuscated Char Count',
        'ObfuscationRatio': 'Obfuscation Ratio',
        'NoOfLettersInURL': 'Letter Count in URL',
        'LetterRatioInURL': 'Letter Ratio',
        'NoOfDegitsInURL': 'Digit Count in URL',
        'DegitRatioInURL': 'Digit Ratio',
        'NoOfEqualsInURL': 'Equals Sign (=) Count',
        'NoOfQMarkInURL': 'Question Mark (?) Count',
        'NoOfAmpersandInURL': 'Ampersand (&) Count',
        'NoOfOtherSpecialCharsInURL': 'Other Special Chars',
        'SpacialCharRatioInURL': 'Special Char Ratio',
        'IsHTTPS': 'HTTPS Protocol'
    };

    featuresGrid.innerHTML = '';
    const feats = data.features || {};

    for (const [key, label] of Object.entries(featureLabels)) {
        if (key in feats) {
            let val = feats[key];
            let isFlagged = false;

            // Flag suspicious characteristics
            if (key === 'IsDomainIP' && val === 1) isFlagged = true;
            if (key === 'HasObfuscation' && val === 1) isFlagged = true;
            if (key === 'IsHTTPS' && val === 0) isFlagged = true;
            if (key === 'NoOfSubDomain' && val > 2) isFlagged = true;

            // Format float decimals cleanly
            if (typeof val === 'number' && !Number.isInteger(val)) {
                val = val.toFixed(4);
            }

            // Yes / No formatting for boolean indicators
            if (key === 'IsDomainIP' || key === 'HasObfuscation' || key === 'IsHTTPS') {
                val = val === 1 ? 'Yes' : 'No';
            }

            const pill = document.createElement('div');
            pill.className = `feature-pill ${isFlagged ? 'flagged' : ''}`;
            pill.innerHTML = `
                <span class="feature-label">${label}</span>
                <span class="feature-val">${val}</span>
            `;
            featuresGrid.appendChild(pill);
        }
    }

    resultSection.classList.remove('hidden');
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
