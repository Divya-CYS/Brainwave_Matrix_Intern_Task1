from flask import Flask, request, jsonify, render_template
import re
import whois
import csv
import os
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)

# === Configuration ===
SUSPICIOUS_KEYWORDS = ['login', 'secure', 'update', 'free', 'verify', 'account', 'bank', 'confirm', 'password']
BLACKLIST_FILE = 'blacklist.txt'
LOG_FILE = 'scan_logs.csv'

# === Utility Functions ===
def load_blacklist():
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'r') as f:
            return [line.strip() for line in f.readlines()]
    return []

def is_valid_url(url):
    regex = re.compile(r'^(http|https)://[^\s/$.?#].[^\s]*$', re.IGNORECASE)
    return re.match(regex, url) is not None

def contains_suspicious_keywords(url):
    return any(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS)

def is_blacklisted(url, blacklist):
    domain = urlparse(url).netloc
    return any(bad_domain in domain for bad_domain in blacklist)

def get_domain_age(url):
    domain = urlparse(url).netloc
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.now() - creation_date).days
        return age
    except:
        return -1

def log_scan(url, result):
    with open(LOG_FILE, 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([datetime.now(), url, result['Final Verdict'], result['Risk Score']])

def scan_url(url):
    blacklist = load_blacklist()

    results = {
        "Uses IP Address": re.match(r'\d+\.\d+\.\d+\.\d+', urlparse(url).netloc) is not None,
        "Suspicious Keywords": contains_suspicious_keywords(url),
        "Blacklisted": is_blacklisted(url, blacklist),
        "Domain Age (days)": get_domain_age(url),
        "Google Indexed": "Unknown"
    }

    risk_score = 0
    if results["Suspicious Keywords"]:
        risk_score += 2
    if results["Blacklisted"]:
        risk_score += 3
    if results["Domain Age (days)"] >= 0 and results["Domain Age (days)"] < 180:
        risk_score += 2

    results["Risk Score"] = risk_score
    results["Final Verdict"] = (
        "⚠️ Phishing Suspected" if risk_score >= 6 else
        "⚠️ Suspicious" if risk_score >= 3 else
        "✅ Likely Safe"
    )

    return results

# === Routes ===

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        url = request.form['url']
        if is_valid_url(url):
            result = scan_url(url)
            log_scan(url, result)
        else:
            result = {"Final Verdict": "❌ Invalid URL"}
    return render_template('index.html', result=result)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    url = data.get('url', '')
    if not is_valid_url(url):
        return jsonify({"status": "Invalid URL"})
    result = scan_url(url)
    log_scan(url, result)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
