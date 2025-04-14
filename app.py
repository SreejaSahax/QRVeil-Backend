from flask import Flask, request, jsonify
from PIL import Image
import joblib
import numpy as np
import re
import requests
import tldextract
from collections import Counter
from math import log2
from sklearn.feature_extraction.text import TfidfVectorizer
from urllib.parse import urlparse
import os

app = Flask(__name__)
MODEL_DIR = "models"

# Load models from the models directory for malicious url detection
model_path = os.path.join(MODEL_DIR, "xgboost_url_model_FINAL.pkl")
vectorizer_path = os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl")

model = joblib.load(model_path)
vectorizer = joblib.load(vectorizer_path)

# Trusted domains
TRUSTED_DOMAINS = {
    "google.com", "wikipedia.org", "netflix.com", "microsoft.com", "youtube.com", "sxccal.edu",
    "facebook.com", "amazon.com", "amazon.in", "chatgpt.com","openai.com", "claude.ai"
}


# URL shorteners
SHORTENERS = {"tinyurl", "bit.ly", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "shorte.st"}

# UPI scheme
VALID_UPI_PREFIX = "upi://pay"

def unshorten_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    if not any(shortener in domain for shortener in SHORTENERS):
        return url

    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        if response.status_code in (301, 302, 303, 307, 308):
            return response.headers.get("Location", url)
        
        response = requests.get(url, allow_redirects=True, timeout=10)
        return response.url
    
    except requests.exceptions.RequestException:
        return "INCORRECT_URL"

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        # Construct the full domain from extracted parts
        domain = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}".strip('.')

        # If missing scheme, assume "https://"
        if not parsed.scheme:
            url = f"https://{domain}{parsed.path}"
            parsed = urlparse(url)  # Re-parse

        # If domain exists and has a valid TLD, it's a valid URL
        if extracted.suffix:  
            return True, url
        
        return False, url
    except:
        return False, url

# Ensure trusted domains and UPI URLs are always safe
def classify_safe_urls(url):
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}".lower()

    # Allow subdomains of trusted domains
    for trusted in TRUSTED_DOMAINS:
        if domain.endswith(trusted):
            return 0  # Trusted domain → Safe

    if url.startswith(VALID_UPI_PREFIX):
        return 0  # UPI URLs → Safe

    return None  # Let other logic decide

def shannon_entropy(text):
    if not text:
        return 0
    freq = Counter(text)
    probs = [f / len(text) for f in freq.values()]
    return -sum(p * log2(p) for p in probs)

def extract_features(url):
    is_valid, url = is_valid_url(url)
    if not is_valid:
        return [-1] * 25

    parsed = tldextract.extract(url)
    domain = parsed.domain.lower()
    path = parsed.suffix.lower() + parsed.subdomain.lower()

    domain_entropy = shannon_entropy(domain)
    path_entropy = shannon_entropy(path)

    # Extract TF-IDF features
    try:
       tfidf_values = vectorizer.transform([url]).toarray()[0]
       if len(tfidf_values) < 3:
           tfidf_values = np.pad(tfidf_values, (0, 3 - len(tfidf_values)), 'constant')  # Pad with zeros
    except:
        tfidf_values = np.zeros(3)  # Default TF-IDF values if transformation fails

    return np.concatenate([
        [
            len(url),
            url.count('.'),
            url.count('-'),
            url.count('@'),
            url.count('?'),
            url.count('='),
            url.count('&'),
            sum(c.isdigit() for c in url),
            sum(c.isalpha() for c in url),
            url.startswith('https'),
            1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
            1 if any(word in url.lower() for word in ['login', 'secure', 'bank', 'verify', 'update']) else 0,
            len(domain.split('.')),
            url.count('/'),
            1 if 'redirect' in url.lower() else 0,
            1 if 'php' in url.lower() or 'asp' in url.lower() or 'jsp' in url.lower() else 0,
            url.count('%'),
            url.count('+'),
            1 if any(ext in url.lower() for ext in ['.exe', '.zip', '.rar', '.apk']) else 0,
            1 if 'free' in url.lower() or 'offer' in url.lower() or 'win' in url.lower() else 0,
            domain_entropy,
            path_entropy,
        ],
        tfidf_values[:3]
    ])


@app.route('/')
def home():
    return '''
        <h1>URL Classification Backend</h1> 
        <p>Available Endpoints:</p>
        <ul>
            <li><strong>/analyze_qr</strong> (POST) - Scan a QR code and classify the URL.</li>
        </ul>
        <p>Supported models:<strong>URL Classification</strong></p>
    '''


@app.route('/analyze_url', methods=['GET','POST'])
def analyze_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data['url']
    print(f"Received URL: {url}")
    
    final_url = unshorten_url(url)
    print(f"Final URL: {final_url}")

    is_valid, url = is_valid_url(final_url)
    if not is_valid:
        return jsonify({"result": "Invalid URL"}), 400

    predefined_label = classify_safe_urls(final_url)
    if predefined_label is not None:
        classification = "Safe URL" if predefined_label == 0 else "Malicious URL detected! Proceed with caution."
    else:
        features = np.array(extract_features(final_url)).reshape(1, -1)
        prediction = model.predict(features)[0]
        classification = "Safe URL" if prediction == 0 else "Malicious URL detected! Proceed with caution."

    return jsonify({"url": final_url, "result": classification})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
