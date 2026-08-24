// extension/popup.js

document.addEventListener('DOMContentLoaded', async () => {
    const loadingBlock = document.getElementById('loading');
    const errorBlock = document.getElementById('error');
    const resultBlock = document.getElementById('result');
    
    const urlText = document.getElementById('url-text');
    const badge = document.getElementById('badge');
    const scoreText = document.getElementById('score-text');
    const reasonsList = document.getElementById('reasons-list');
    
    const btnScan = document.getElementById('btn-scan');
    const btnRetry = document.getElementById('btn-retry');

    // Get current active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab || tab.url.startsWith('chrome://')) {
        showError("ThreatLens cannot scan Chrome system pages.");
        return;
    }
    
    // Check if background script already has a result for this tab
    chrome.runtime.sendMessage({ action: 'GET_TAB_RESULT', tabId: tab.id }, (response) => {
        if (response) {
            renderResult(tab.url, response);
        } else {
            // No result yet, tell content script to analyze
            triggerScan(tab);
        }
    });
    
    function triggerScan(tab) {
        showLoading();
        // Ask content script for data, which forwards to background
        chrome.tabs.sendMessage(tab.id, { action: 'REQUEST_PAGE_DATA' }, (response) => {
            if (chrome.runtime.lastError) {
                // Content script not loaded (e.g. extension just installed)
                // Force a scan based just on URL
                chrome.runtime.sendMessage({ action: 'FORCE_SCAN', tabId: tab.id, url: tab.url });
            }
        });
    }

    // Listen for SCAN_COMPLETE from background
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === 'SCAN_COMPLETE' && request.tabId === tab.id) {
            renderResult(tab.url, request.result);
        }
    });

    btnScan.addEventListener('click', () => triggerScan(tab));
    btnRetry.addEventListener('click', () => triggerScan(tab));

    function renderResult(url, data) {
        loadingBlock.classList.add('hidden');
        errorBlock.classList.add('hidden');
        resultBlock.classList.remove('hidden');

        // URL display
        urlText.textContent = url.length > 40 ? url.substring(0, 37) + '...' : url;

        // Badge
        badge.textContent = data.verdict;
        badge.className = 'badge';
        if (data.verdict === 'SAFE') badge.classList.add('v-safe');
        else if (data.verdict === 'SUSPICIOUS') badge.classList.add('v-suspicious');
        else if (data.verdict === 'HIGH RISK') badge.classList.add('v-high');
        else badge.classList.add('v-dangerous');

        // Score
        scoreText.textContent = data.risk_score;

        // Reasons
        reasonsList.innerHTML = '';
        if (data.reasons && data.reasons.length > 0) {
            data.reasons.forEach(r => {
                const li = document.createElement('li');
                li.textContent = r;
                reasonsList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = "No specific indicators found.";
            li.style.color = "var(--text-faint)";
            reasonsList.appendChild(li);
        }
    }

    function showLoading() {
        loadingBlock.classList.remove('hidden');
        errorBlock.classList.add('hidden');
        resultBlock.classList.add('hidden');
    }

    function showError(msg) {
        loadingBlock.classList.add('hidden');
        resultBlock.classList.add('hidden');
        errorBlock.classList.remove('hidden');
        if (msg) {
            errorBlock.querySelector('p').textContent = msg;
        }
    }
});
