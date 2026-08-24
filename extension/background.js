// extension/background.js

// API URL for production: https://sih-l2l2.onrender.com/api/scan
// For local dev: http://127.0.0.1:5000/api/scan
// To switch to production, change the URL below:
const API_URL = "http://127.0.0.1:5000/api/scan";

// Cache for scan results per tab
let tabResults = {};

function updateBadge(tabId, verdict) {
    let text = "";
    let color = "";
    
    switch(verdict) {
        case "SAFE":
            text = "✓";
            color = "#3ED88F"; // Turquoise/Green
            break;
        case "SUSPICIOUS":
            text = "?";
            color = "#F5A623"; // Orange
            break;
        case "HIGH RISK":
            text = "!";
            color = "#FF4B4B"; // Light Red
            break;
        case "DANGEROUS":
            text = "!!";
            color = "#D0021B"; // Dark Red
            break;
    }
    
    if (text) {
        chrome.action.setBadgeText({ text: text, tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
    }
}

async function scanUrl(url, tabId, domData) {
    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url }) // sending URL; backend phase 5 focuses on URL structure
        });
        
        if (!response.ok) {
            throw new Error("API Error");
        }
        
        const result = await response.json();
        
        if (result.success) {
            // Include domData just so popup can see it if we want
            result.domData = domData;
            
            // Store result for this tab
            tabResults[tabId] = result;
            
            // Update the extension badge
            updateBadge(tabId, result.verdict);
            
            // Send back to popup if it's open
            chrome.runtime.sendMessage({ action: 'SCAN_COMPLETE', tabId: tabId, result: result });
            
            // Send to content script for potential prevention overlay
            chrome.tabs.sendMessage(tabId, { action: 'SHOW_PREVENTION', result: result }).catch(e => {});
        }
    } catch (err) {
        console.error("ThreatLens Scan Failed:", err);
    }
}

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'PAGE_ANALYZED') {
        if (sender.tab && sender.tab.url && !sender.tab.url.startsWith("chrome://")) {
            scanUrl(sender.tab.url, sender.tab.id, request.data);
        }
    }
    
    if (request.action === 'GET_TAB_RESULT') {
        if (request.tabId && tabResults[request.tabId]) {
            sendResponse(tabResults[request.tabId]);
        } else {
            sendResponse(null);
        }
    }
    
    if (request.action === 'FORCE_SCAN') {
        scanUrl(request.url, request.tabId, null);
        sendResponse({status: "started"});
    }
});

// Clean up memory when tabs close
chrome.tabs.onRemoved.addListener((tabId) => {
    delete tabResults[tabId];
});
