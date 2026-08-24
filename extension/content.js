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

// Listen for requests from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'REQUEST_PAGE_DATA') {
        sendResponse(analyzePage());
    }
});
