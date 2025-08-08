# app.py - Enhanced URL Safety Checker
from flask import Flask, request, jsonify
import requests
import os
import time
import re
from urllib.parse import urlparse
import hashlib

app = Flask(__name__)

# Environment variables for API keys
VIRUSTOTAL_KEY = os.environ.get("VT_KEY")
GSB_KEY = os.environ.get("GSB_KEY")

def validate_url(url):
    """Basic URL validation and normalization"""
    if not url:
        return None, "No URL provided"
    
    # Add protocol if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    # Basic URL pattern validation
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if not url_pattern.match(url):
        return None, "Invalid URL format"
    
    return url, None

def check_google_safe_browsing(url):
    """Check URL against Google Safe Browsing API"""
    if not GSB_KEY:
        return {"error": "Google Safe Browsing API key not configured"}
    
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    body = {
        "client": {
            "clientId": "url-safety-checker",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    params = {"key": GSB_KEY}
    
    try:
        response = requests.post(endpoint, params=params, json=body, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Google Safe Browsing API error: {str(e)}"}

def check_virustotal(url):
    """Check URL against VirusTotal API"""
    if not VIRUSTOTAL_KEY:
        return {"error": "VirusTotal API key not configured"}
    
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    
    try:
        # Submit URL for analysis
        submit_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=15
        )
        submit_response.raise_for_status()
        
        analysis_id = submit_response.json().get("data", {}).get("id")
        if not analysis_id:
            return {"error": "Failed to get analysis ID from VirusTotal"}
        
        # Get analysis results
        analysis_response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=15
        )
        analysis_response.raise_for_status()
        
        return analysis_response.json()
        
    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal API error: {str(e)}"}

def calculate_safety_score(google_result, virustotal_result):
    """Calculate safety score based on API results"""
    score = 100
    threats_found = []
    
    # Check Google Safe Browsing results
    if google_result and not google_result.get("error"):
        matches = google_result.get("matches", [])
        if matches:
            score -= 70
            for match in matches:
                threat_type = match.get("threatType", "Unknown threat")
                threats_found.append(f"Google: {threat_type}")
    
    # Check VirusTotal results
    if virustotal_result and not virustotal_result.get("error"):
        try:
            data = virustotal_result.get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            if malicious > 0:
                score -= min(malicious * 15, 80)
                threats_found.append(f"VirusTotal: {malicious} engines flagged as malicious")
            
            if suspicious > 0:
                score -= min(suspicious * 5, 20)
                threats_found.append(f"VirusTotal: {suspicious} engines flagged as suspicious")
                
        except (KeyError, TypeError):
            pass
    
    return max(score, 0), threats_found

def get_safety_rating(score):
    """Convert numeric score to readable safety rating"""
    if score >= 90:
        return "Safe"
    elif score >= 70:
        return "Likely Safe"
    elif score >= 50:
        return "Caution"
    elif score >= 30:
        return "Risky"
    else:
        return "Dangerous"

@app.route("/api/check", methods=["POST"])
def check_url():
    """Main endpoint for URL safety checking"""
    data = request.json or {}
    url = data.get("url", "").strip()
    
    # Validate URL
    normalized_url, error = validate_url(url)
    if error:
        return jsonify({"error": error}), 400
    
    # Initialize results
    results = {
        "url": normalized_url,
        "timestamp": int(time.time()),
        "checks": {}
    }
    
    # Check Google Safe Browsing
    try:
        google_result = check_google_safe_browsing(normalized_url)
        results["checks"]["google_safe_browsing"] = google_result
    except Exception as e:
        results["checks"]["google_safe_browsing"] = {"error": f"Unexpected error: {str(e)}"}
    
    # Check VirusTotal
    try:
        vt_result = check_virustotal(normalized_url)
        results["checks"]["virustotal"] = vt_result
    except Exception as e:
        results["checks"]["virustotal"] = {"error": f"Unexpected error: {str(e)}"}
    
    # Calculate safety score
    score, threats = calculate_safety_score(
        results["checks"]["google_safe_browsing"],
        results["checks"]["virustotal"]
    )
    
    results["safety_score"] = score
    results["safety_rating"] = get_safety_rating(score)
    results["threats_found"] = threats
    
    return jsonify(results)

@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "apis_configured": {
            "google_safe_browsing": bool(GSB_KEY),
            "virustotal": bool(VIRUSTOTAL_KEY)
        }
    })

@app.route("/", methods=["GET"])
def index():
    """Simple web interface for testing"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>URL Safety Checker</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            input[type="text"] { width: 60%; padding: 10px; font-size: 16px; }
            button { padding: 10px 20px; font-size: 16px; margin-left: 10px; }
            .result { margin-top: 20px; padding: 15px; border-radius: 5px; }
            .safe { background-color: #d4edda; border: 1px solid #c3e6cb; }
            .caution { background-color: #fff3cd; border: 1px solid #ffeaa7; }
            .dangerous { background-color: #f8d7da; border: 1px solid #f5c6cb; }
        </style>
    </head>
    <body>
        <h1>URL Safety Checker</h1>
        <p>Enter a URL to check its safety rating using Google Safe Browsing and VirusTotal APIs.</p>
        
        <input type="text" id="urlInput" placeholder="https://example.com" />
        <button onclick="checkUrl()">Check URL</button>
        
        <div id="result"></div>
        
        <script>
        async function checkUrl() {
            const url = document.getElementById('urlInput').value;
            const resultDiv = document.getElementById('result');
            
            if (!url) {
                resultDiv.innerHTML = '<div class="result">Please enter a URL</div>';
                return;
            }
            
            resultDiv.innerHTML = '<div class="result">Checking...</div>';
            
            try {
                const response = await fetch('/api/check', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url})
                });
                
                const data = await response.json();
                
                if (data.error) {
                    resultDiv.innerHTML = `<div class="result dangerous">Error: ${data.error}</div>`;
                    return;
                }
                
                let cssClass = 'safe';
                if (data.safety_score < 70) cssClass = 'caution';
                if (data.safety_score < 50) cssClass = 'dangerous';
                
                let threatsHtml = '';
                if (data.threats_found && data.threats_found.length > 0) {
                    threatsHtml = '<h4>Threats Found:</h4><ul>';
                    data.threats_found.forEach(threat => {
                        threatsHtml += `<li>${threat}</li>`;
                    });
                    threatsHtml += '</ul>';
                }
                
                resultDiv.innerHTML = `
                    <div class="result ${cssClass}">
                        <h3>Safety Check Results</h3>
                        <p><strong>URL:</strong> ${data.url}</p>
                        <p><strong>Safety Score:</strong> ${data.safety_score}/100</p>
                        <p><strong>Safety Rating:</strong> ${data.safety_rating}</p>
                        ${threatsHtml}
                    </div>
                `;
            } catch (error) {
                resultDiv.innerHTML = `<div class="result dangerous">Error: ${error.message}</div>`;
            }
        }
        
        document.getElementById('urlInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                checkUrl();
            }
        });
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    # Check if API keys are configured
    if not VIRUSTOTAL_KEY:
        print("Warning: VT_KEY environment variable not set")
    if not GSB_KEY:
        print("Warning: GSB_KEY environment variable not set")
    
    app.run(debug=True, host="0.0.0.0", port=5001)