import base64
import requests
import firebase_admin
from firebase_admin import credentials, firestore
from flask import Flask, request, jsonify
from flask_cors import CORS  # Import CORS
from datetime import datetime
# Initialize Flask App
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "https://virus-aics.web.app"}})
# Load Firebase

# Initialize coupon codes collection
COUPON_CODES = {
    "phis7d": {"MAX_USES": 3},  # Existing coupon code
    "phistrial": {"MAX_USES": 3},  # New coupon code
    "newuser": {"MAX_USES": 3},  # New coupon code
    "trial": {"MAX_USES": 3}  # New coupon code
}

# VirusTotal API Key (hardcoded directly in the code 25be5ec8d04d39c8b272ba0d5323364ab759eab00540c98abf551ec2c9c8cbaf)4e870c6da30320112c87f9d662aabf5efbad0cf651eafd61ee7a6ee50da4331f 
VIRUS_TOTAL_API_KEY = "22abddfd9a6bd0923b3404e35522e6b4b45abe7738fb5675f1b0b500bc44435f"

# Function to check URL with VirusTotal API
def check_url_with_virustotal(url):
    # Encode URL to base64
    url_base64 = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    virus_total_url = f"https://www.virustotal.com/api/v3/urls/{url_base64}"
    headers = {"x-apikey": VIRUS_TOTAL_API_KEY}
    response = requests.get(virus_total_url, headers=headers)
    
    if response.status_code != 200:
        return None, f"Error with VirusTotal API: {response.text}"
    
    return response.json(), None
@app.route("/validate_coupon", methods=["POST"])
def validate_coupon():
    data = request.json
    coupon = data.get("coupon", "").strip()

    if not coupon:
        return jsonify({"error": "No coupon provided."}), 400

    if coupon not in COUPON_CODES:
        return jsonify({"error": "Invalid coupon."}), 400

    coupon_data = COUPON_CODES[coupon]
    max_uses = coupon_data["MAX_USES"]
    coupon_ref = db.collection("coupons").document(coupon)
    coupon_doc = coupon_ref.get()

    if not coupon_doc.exists:
        # First time use, create it
        coupon_ref.set({
            "uses": 1,
            "created_at": datetime.now()
        })
        return jsonify({"message": "Coupon accepted.", "remaining_uses": max_uses - 1})

    coupon_data = coupon_doc.to_dict()
    uses = coupon_data.get("uses", 0)

    if uses >= max_uses:
        return jsonify({"error": "Coupon has reached its usage limit."}), 400

    # Increment usage
    coupon_ref.update({"uses": uses + 1})
    return jsonify({"message": "Coupon accepted.", "remaining_uses": max_uses - (uses + 1)})
@app.route("/check_url", methods=["POST"])
def check_url():
    data = request.json
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Check URL with VirusTotal
    virus_total_result, error = check_url_with_virustotal(url)
    if error:
        return jsonify({"error": error}), 500

    # Determine if the URL is phishing based on VirusTotal analysis
    is_phishing = "data" in virus_total_result and "attributes" in virus_total_result["data"] and virus_total_result["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0

    malicious_info = virus_total_result["data"]["attributes"].get("last_analysis_results", {})
    detection_details = virus_total_result["data"]["attributes"].get("last_analysis_stats", {})
    additional_info = virus_total_result["data"]["attributes"].get("tags", [])

    # Store the URL and its status in Firestore
    db.collection("phishing_reports").add({
        "url": url,
        "is_phishing": is_phishing,
        "timestamp": firestore.SERVER_TIMESTAMP
    })

    message = "Phishing detected!" if is_phishing else "Safe URL"

    return jsonify({
        "url": url,
        "is_phishing": is_phishing,
        "message": message,
        "malicious_info": malicious_info,
        "detection_details": detection_details,
        "additional_info": additional_info,
    })


@app.route("/get_url_history", methods=["GET"])
def get_url_history():
    phishing_reports_ref = db.collection("phishing_reports")
    reports = phishing_reports_ref.stream()

    history = []
    for report in reports:
        report_data = report.to_dict()
        history.append({
            "url": report_data.get("url"),
            "is_phishing": report_data.get("is_phishing"),
            "timestamp": report_data.get("timestamp")
        })

    return jsonify({"url_history": history})

@app.route("/analyze_email", methods=["POST"])
def analyze_email():
    data = request.json
    email_content = data.get("email_content", "").lower()

    if not email_content:
        return jsonify({"error": "No email content provided"}), 400

    # Define phishing keywords to check in the email content
    phishing_keywords = ["verify your account", "click here", "urgent", "reset your password", "suspicious activity"]
    is_phishing = any(keyword in email_content for keyword in phishing_keywords)

    # Additional output - List of detected phishing keywords
    detected_keywords = [keyword for keyword in phishing_keywords if keyword in email_content]

    return jsonify({
        "email_content": email_content[:50] + "...",  # Display only the first 50 characters for brevity
        "is_phishing": is_phishing,
        "message": "Potential phishing email!" if is_phishing else "Looks safe",
        "detected_phishing_keywords": detected_keywords  # Additional output for detected phishing keywords
    })

if __name__ == "__main__":
    app.run(debug=True)
