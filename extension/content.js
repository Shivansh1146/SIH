// extension/content.js

function analyzePage() {
    // 1. Password input count
    const passwordInputs = document.querySelectorAll('input[type="password"]').length;
    
    // 2. OTP-related inputs
    const otpKeywords = ['otp', 'code', 'verification', 'auth', '2fa', 'mfa'];
    const textInputs = document.querySelectorAll('input[type="text"], input[type="number"]');
    let otpInputs = 0;
    textInputs.forEach(input => {
        const name = (input.name || '').toLowerCase();
        const id = (input.id || '').toLowerCase();
        if (otpKeywords.some(kw => name.includes(kw) || id.includes(kw))) {
            otpInputs++;
        }
    });

    // 3. Page text snippet (first 1000 characters)
    const pageText = document.body.innerText.substring(0, 1000).toLowerCase();

    // 4. Login-related keywords
    const loginKeywords = ['login', 'sign in', 'password', 'secure', 'verify', 'account'];
    const foundKeywords = loginKeywords.filter(kw => pageText.includes(kw));

    // Compile payload
    const payload = {
        url: window.location.href,
        title: document.title,
        password_input_count: passwordInputs,
        otp_input_count: otpInputs,
        page_text_snippet: pageText.substring(0, 200), // even shorter for background
        found_login_keywords: foundKeywords
    };

    // Send to background for processing / caching
    chrome.runtime.sendMessage({ action: 'PAGE_ANALYZED', data: payload });
    
    return payload;
}

// Automatically analyze the page on load
analyzePage();

// Listen for messages
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'REQUEST_PAGE_DATA') {
        sendResponse(analyzePage());
    }
    
    if (request.action === 'SHOW_PREVENTION' && request.result) {
        if (request.result.risk_score >= 60) {
            injectWarningOverlay(request.result);
        }
    }
});

function injectWarningOverlay(data) {
    // Only inject once
    if (document.getElementById('threatlens-warning-overlay')) return;

    const overlay = document.createElement('div');
    overlay.id = 'threatlens-warning-overlay';
    
    const isDangerous = data.risk_score >= 80;
    const accentColor = isDangerous ? '#D0021B' : '#FF4B4B';
    const title = isDangerous ? 'DANGEROUS WEBSITE' : 'HIGH RISK WEBSITE';
    const subtitle = isDangerous ? 'This website appears dangerous.' : 'This website shows high-risk indicators.';

    let reasonsHtml = '';
    if (data.reasons && data.reasons.length > 0) {
        reasonsHtml = '<ul style="margin: 16px 0; padding-left: 20px; text-align: left; font-size: 14px; color: #f3f4f6;">';
        data.reasons.forEach(r => {
            reasonsHtml += `<li style="margin-bottom: 8px;">${r}</li>`;
        });
        reasonsHtml += '</ul>';
    }

    overlay.innerHTML = `
        <div style="position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(10, 14, 19, 0.95); z-index: 2147483647; display: flex; align-items: center; justify-content: center; font-family: -apple-system, sans-serif;">
            <div style="background: #121820; border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 40px; max-width: 500px; text-align: center; color: #fff; box-shadow: 0 20px 40px rgba(0,0,0,0.5);">
                <div style="width: 64px; height: 64px; background: rgba(${isDangerous ? '208,2,27' : '255,75,75'},0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 24px;">
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="${accentColor}" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                </div>
                <h1 style="font-size: 20px; letter-spacing: 1px; color: ${accentColor}; margin: 0 0 8px 0; text-transform: uppercase;">⚠ THREATLENS WARNING</h1>
                <p style="font-size: 18px; margin: 0 0 24px 0;">${subtitle}</p>
                
                <div style="background: rgba(255,255,255,0.03); padding: 20px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.05); margin-bottom: 32px;">
                    <div style="font-size: 12px; color: #9CA3AF; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Risk Score</div>
                    <div style="font-size: 32px; font-weight: bold; margin-bottom: 16px;">${data.risk_score} <span style="font-size: 16px; color: #9CA3AF; font-weight: normal;">/ 100</span></div>
                    
                    <div style="font-size: 12px; color: #9CA3AF; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Why?</div>
                    ${reasonsHtml}
                </div>
                
                <div style="display: flex; gap: 16px;">
                    <button id="tl-btn-back" style="flex: 1; padding: 14px; background: ${accentColor}; color: white; border: none; border-radius: 4px; font-size: 15px; font-weight: bold; cursor: pointer;">Go Back</button>
                    <button id="tl-btn-continue" style="flex: 1; padding: 14px; background: transparent; color: #9CA3AF; border: 1px solid rgba(255,255,255,0.2); border-radius: 4px; font-size: 15px; cursor: pointer;">Continue Anyway</button>
                </div>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById('tl-btn-back').addEventListener('click', () => {
        if (window.history.length > 1) {
            window.history.back();
        } else {
            window.location.href = 'about:blank';
        }
    });

    document.getElementById('tl-btn-continue').addEventListener('click', () => {
        overlay.remove();
    });
}
