# app.py - Enhanced URL Safety Checker
from flask import Flask, request, jsonify, render_template
from functions import validate_url, check_google_safe_browsing, check_virustotal
from functions import calculate_safety_score, get_safety_rating, GSB_KEY, VIRUSTOTAL_KEY
import time

app = Flask(__name__)

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
    return render_template("index.html")

if __name__ == "__main__":
    # Check if API keys are configured
    if not VIRUSTOTAL_KEY:
        print("Warning: VT_KEY environment variable not set")
    if not GSB_KEY:
        print("Warning: GSB_KEY environment variable not set")
    
    app.run(debug=True, host="0.0.0.0", port=5001)