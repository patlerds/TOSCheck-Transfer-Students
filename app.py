import os
import requests
import hashlib
import json
import time
from flask import Flask, request, jsonify, render_template
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

# Initialize Flask app
app = Flask(__name__)
# Get the API key from environment variables or use an empty string for Canvas
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

# Directory for caching results
CACHE_DIR = './cache'
os.makedirs(CACHE_DIR, exist_ok=True)

# In-memory dictionary to track job statuses (for simplicity; a real app might use Redis/DB)
job_status = {}
job_results = {}

# Thread pool for asynchronous tasks
executor = ThreadPoolExecutor(max_workers=5)

# --- Helper Functions ---

def generate_url_hash(url):
    """Generates a SHA256 hash for a given URL."""
    return hashlib.sha256(url.encode()).hexdigest()

def get_cache_paths(url_hash):
    """Returns paths for raw HTML and analysis JSON in the cache."""
    hash_dir = os.path.join(CACHE_DIR, url_hash)
    os.makedirs(hash_dir, exist_ok=True)
    return {
        "dir": hash_dir,
        "raw_html": os.path.join(hash_dir, "raw.html"),
        "analysis_json": os.path.join(hash_dir, "analysis.json")
    }

def scrape_document(url):
    """
    Fetches HTML content from a URL and extracts main text.
    Includes polite delays and basic error handling.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        # Add a small delay to be polite
        time.sleep(1)
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)

        soup = BeautifulSoup(response.text, 'html.parser')

        # Try to extract text from common content areas
        content_tags = ['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li', 'div']
        text_parts = []
        for tag in soup.find_all(content_tags):
            # Heuristic to avoid navigation/footer: check parent's ID/class
            # This is a basic approach and might need refinement for specific sites
            parent_id = tag.find_parent(id=True)
            parent_class = tag.find_parent(class_=True)
            if parent_id and "nav" in parent_id.get('id', '').lower():
                continue
            if parent_class and any(c in ["header", "footer", "navbar", "sidebar"] for c in parent_class.get('class', [])):
                continue
            text_parts.append(tag.get_text(separator=' ', strip=True))

        document_text = "\n\n".join(text_parts)

        # Fallback if no specific content is found: just get all text
        if not document_text.strip():
            document_text = soup.get_text(separator=' ', strip=True)

        return response.text, document_text

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error scraping {url}: {e}")
        raise ValueError(f"Failed to scrape content from the URL: {e}")

def call_gemini_api(prompt, document_text, response_schema=None):
    """
    Calls the Gemini API with a given prompt and document text,
    optionally enforcing a JSON schema.
    """
    # Use gemini-2.0-flash as specified in the design doc
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"

    chat_history = []
    chat_history.push({ "role": "user", "parts": [{ "text": prompt + "\n\nDocument Text:\n" + document_text }] })
    payload = {
        "contents": chat_history
    }
    if response_schema:
        payload["generationConfig"] = {
            "responseMimeType": "application/json",
            "responseSchema": response_schema
        }

    try:
        response = requests.post(api_url, json=payload, headers={'Content-Type': 'application/json'})
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        result = response.json()

        if result.get("candidates") and result["candidates"][0].get("content") and result["candidates"][0]["content"].get("parts"):
            text_response = result["candidates"][0]["content"]["parts"][0]["text"]
            if response_schema:
                return json.loads(text_response) # Parse JSON if schema was used
            return text_response
        else:
            app.logger.warning(f"Unexpected Gemini API response structure: {result}")
            return None
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Gemini API request failed: {e}")
        raise ValueError(f"Gemini API request failed: {e}")
    except json.JSONDecodeError as e:
        app.logger.error(f"Failed to decode JSON from Gemini API: {e}")
        raise ValueError(f"Failed to parse Gemini API response: {e}")

def analyze_document_task(url, job_id):
    """
    Background task to scrape, analyze, and cache a legal document.
    Updates job_status and job_results.
    """
    job_status[job_id] = "scraping"
    try:
        full_html, document_text = scrape_document(url)
        cache_paths = get_cache_paths(job_id)

        # Save raw HTML
        with open(cache_paths["raw_html"], "w", encoding="utf-8") as f:
            f.write(full_html)

        job_status[job_id] = "analyzing"

        # 1. Overall Summary
        summary_prompt = "Provide a concise, consumer-friendly summary of the following legal document (Privacy Policy or Terms of Service)."
        overall_summary = call_gemini_api(summary_prompt, document_text)

        # 2. Data Collection & Processing
        data_collection_schema = {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "dataType": {"type": "STRING"},
                    "purpose": {"type": "STRING"}
                },
                "required": ["dataType", "purpose"]
            }
        }
        data_collection_prompt = "Analyze the following legal document and identify all types of personal data collected and processed. For each data type, describe its purpose of collection and processing. Return the information as a JSON array of objects with 'dataType' and 'purpose'."
        data_collection_analysis = call_gemini_api(data_collection_prompt, document_text, data_collection_schema)

        # 3. Data Selling/Sharing
        data_sharing_schema = {
            "type": "OBJECT",
            "properties": {
                "canBeSharedOrSold": {"type": "BOOLEAN"},
                "dataTypes": {"type": "ARRAY", "items": {"type": "STRING"}},
                "conditions": {"type": "STRING"}
            },
            "required": ["canBeSharedOrSold"]
        }
        data_sharing_prompt = "Based on the following legal document, does the service/website explicitly state it shares or sells user data to third parties? If yes, specify what types of data are shared/sold and under what conditions. Return the information as a JSON object with 'canBeSharedOrSold' (boolean), 'dataTypes' (array of strings, if applicable), and 'conditions' (string, if applicable)."
        data_sharing_analysis = call_gemini_api(data_sharing_prompt, document_text, data_sharing_schema)

        # 4. Suspicious Terms
        suspicious_terms_schema = {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "term": {"type": "STRING"},
                    "explanation": {"type": "STRING"}
                },
                "required": ["term", "explanation"]
            }
        }
        suspicious_terms_prompt = "Review the following legal document for any unusual, ambiguous, or potentially unfavorable legal terms or clauses for a consumer. For each identified term, explain why it might be suspicious or require extra attention. Return the information as a JSON array of objects with 'term' and 'explanation'."
        suspicious_terms_analysis = call_gemini_api(suspicious_terms_prompt, document_text, suspicious_terms_schema)

        # Combine all analysis results
        combined_analysis = {
            "summary": overall_summary,
            "data_collection": data_collection_analysis,
            "data_sharing": data_sharing_analysis,
            "suspicious_terms": suspicious_terms_analysis,
            "timestamp": time.time() # Add timestamp for potential future invalidation
        }

        # Save combined analysis
        with open(cache_paths["analysis_json"], "w", encoding="utf-8") as f:
            json.dump(combined_analysis, f, indent=4)

        job_results[job_id] = combined_analysis
        job_status[job_id] = "completed"

    except Exception as e:
        app.logger.error(f"Error processing job {job_id} for URL {url}: {e}")
        job_status[job_id] = "failed"
        job_results[job_id] = {"error": str(e)}

# --- Flask Routes ---

@app.route('/')
def index():
    """Serves the main HTML page."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_document():
    """
    Receives a URL, checks cache, and initiates analysis.
    """
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({"error": "URL is required"}), 400

    # Basic URL validation (can be more robust)
    if not (url.startswith('http://') or url.startswith('https://')):
        return jsonify({"error": "Invalid URL format. Must start with http:// or https://"}), 400

    job_id = generate_url_hash(url)
    cache_paths = get_cache_paths(job_id)

    # Check cache first
    if os.path.exists(cache_paths["analysis_json"]):
        try:
            with open(cache_paths["analysis_json"], "r", encoding="utf-8") as f:
                cached_analysis = json.load(f)
            # You could add cache invalidation logic here (e.g., check timestamp)
            app.logger.info(f"Cache hit for {url}")
            return jsonify({"job_id": job_id, "status": "completed", "result": cached_analysis})
        except json.JSONDecodeError as e:
            app.logger.warning(f"Corrupted cache file for {job_id}: {e}. Re-analyzing.")
            # Fall through to re-analysis if cache is corrupted

    # If not in cache or corrupted, start a new analysis task
    app.logger.info(f"Starting new analysis for {url}")
    job_status[job_id] = "pending"
    job_results[job_id] = None # Clear any old results
    executor.submit(analyze_document_task, url, job_id)

    return jsonify({"job_id": job_id, "status": "processing"}), 202

@app.route('/status/<job_id>', methods=['GET'])
def get_job_status(job_id):
    """
    Returns the current status of an analysis job.
    """
    status = job_status.get(job_id, "unknown")
    if status == "unknown":
        # Also check if it's completed in cache, even if not in memory
        cache_paths = get_cache_paths(job_id)
        if os.path.exists(cache_paths["analysis_json"]):
            status = "completed"
            app.logger.info(f"Job {job_id} found as completed in cache during status check.")
    return jsonify({"job_id": job_id, "status": status})

@app.route('/result/<job_id>', methods=['GET'])
def get_job_result(job_id):
    """
    Returns the analysis result for a completed job.
    """
    status = job_status.get(job_id)
    if status == "completed":
        result = job_results.get(job_id)
        if result:
            return jsonify(result)
        else:
            # Try to load from cache if it was completed and then server restarted
            cache_paths = get_cache_paths(job_id)
            if os.path.exists(cache_paths["analysis_json"]):
                try:
                    with open(cache_paths["analysis_json"], "r", encoding="utf-8") as f:
                        cached_analysis = json.load(f)
                    job_results[job_id] = cached_analysis # Populate in-memory cache
                    return jsonify(cached_analysis)
                except json.JSONDecodeError:
                    return jsonify({"error": "Analysis result corrupted in cache."}), 500
            return jsonify({"error": "Analysis result not found."}), 404
    elif status == "failed":
        return jsonify({"error": job_results.get(job_id, {}).get("error", "Analysis failed.")}), 500
    else:
        return jsonify({"error": "Analysis still in progress or not found.", "status": status}), 409 # Conflict

if __name__ == '__main__':
    # For development, run with debug=True
    # In a production environment, use a WSGI server like Gunicorn
    app.run(debug=True, port=5000)
