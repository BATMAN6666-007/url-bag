import os
import requests
import re


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