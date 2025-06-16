# app.py
import os
import hashlib
import json
import requests
import time
from flask import Flask, request, jsonify, render_template
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import asyncio
import threading
import concurrent.futures

# Load environment variables from .env file (for API key during local development)
load_dotenv()

app = Flask(__name__)

# Configuration
CACHE_DIR = './cache'
os.makedirs(CACHE_DIR, exist_ok=True) # Ensure cache directory exists

# Gemini API Key - In production, this should be handled securely, e.g., from environment variables
# For Canvas environment, an empty string will allow the platform to inject it.

GEMINI_API_KEY = None

if not GEMINI_API_KEY:
    # A list of possible locations for the gemini.txt file
    key_locations = [
        os.path.join(os.path.dirname(__file__), '..', 'gemini.txt'),
        '/home/nish/web/gemini.txt',
    ]

    # Loop through the locations and use the first key found
    for file_path in key_locations:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                GEMINI_API_KEY = f.read().strip()
            if GEMINI_API_KEY:
                break # Exit loop once key is found

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent"

# In-memory dictionary to track job statuses for asynchronous tasks
# In a real-world scenario with multiple Flask workers, this would need a shared, persistent store (e.g., Redis)
job_statuses = {}

# Thread pool for running blocking I/O tasks like scraping and LLM calls
# This helps prevent blocking the main Flask thread when using a non-async Flask setup.
executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)


def get_gemini_api_key():
    """
    Retrieves the Gemini API key.
    If running in a Canvas environment, the platform injects it.
    Otherwise, it tries to load from an environment variable or a local file.
    """
    if GEMINI_API_KEY: # Check if it's already set (e.g. from .env)
        return GEMINI_API_KEY
    # For Canvas, the __api_key__ global variable is injected
    return os.environ.get("__api_key__", "")


def get_document_text(url):
    """
    Fetches HTML content from a given URL and extracts the main text content.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Attempt to extract main content. This is a heuristic and might need refinement
        # for different website structures.
        main_content = soup.find('article') or soup.find('main') or soup.find('body')

        if not main_content:
            return "Could not extract main content from the page."

        # Extract text from paragraphs, headings, and list items
        paragraphs = main_content.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li'])
        text_content = "\n".join([elem.get_text(separator=" ", strip=True) for elem in paragraphs])

        # Basic sanitization to remove excessive whitespace
        text_content = ' '.join(text_content.split())
        return text_content

    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        return None
    except Exception as e:
        print(f"Error processing content for {url}: {e}")
        return None


def call_gemini_api(document_text, prompt_type):
    """
    Calls the Gemini API with the given document text and a specific prompt type.
    """
    api_key = get_gemini_api_key()
    if not api_key:
        print("Gemini API Key not found. Please set GEMINI_API_KEY or ensure it's injected by Canvas.")
        return {"error": "Gemini API Key not configured."}

    # Define prompts and schemas based on the design document
    prompts = {
        "summary": {
            "text": "Summarize the following legal document concisely and in consumer-friendly language. Focus on the most important aspects for an average user.",
            "schema": {
                "type": "OBJECT",
                "properties": {
                    "summary": {"type": "STRING"}
                },
                "required": ["summary"]
            }
        },
        "data_collection": {
            "text": "Analyze the following legal document and identify all types of personal data collected and processed. For each data type, describe its purpose of collection and processing. Return the information as a JSON array of objects with 'dataType' and 'purpose'.",
            "schema": {
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
        },
        "data_sharing": {
            "text": "Based on the following legal document, does the service/website explicitly state it shares or sells user data to third parties? If yes, specify what types of data are shared/sold and under what conditions. Return the information as a JSON object with 'canBeSharedOrSold' (boolean), 'dataTypes' (array of strings, if applicable), and 'conditions' (string, if applicable).",
            "schema": {
                "type": "OBJECT",
                "properties": {
                    "canBeSharedOrSold": {"type": "BOOLEAN"},
                    "dataTypes": {"type": "ARRAY", "items": {"type": "STRING"}},
                    "conditions": {"type": "STRING"}
                },
                "required": ["canBeSharedOrSold"]
            }
        },
        "suspicious_terms": {
            "text": "Review the following legal document for any unusual, ambiguous, or potentially unfavorable legal terms or clauses for a consumer. For each identified term, explain why it might be suspicious or require extra attention. Return the information as a JSON array of objects with 'term' and 'explanation'.",
            "schema": {
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
        }
    }

    if prompt_type not in prompts:
        return {"error": f"Invalid prompt type: {prompt_type}"}

    prompt_config = prompts[prompt_type]
    full_prompt = prompt_config["text"] + "\n\nDocument Text:\n" + document_text

    payload = {
        "contents": [{"role": "user", "parts": [{"text": full_prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": prompt_config["schema"]
        }
    }

    try:
        response = requests.post(
            f"{GEMINI_API_URL}?key={api_key}",
            headers={'Content-Type': 'application/json'},
            json=payload,
            timeout=300 # Increased timeout for potentially longer LLM responses
        )
        response.raise_for_status()
        result = response.json()

        if result and result.get("candidates") and result["candidates"][0].get("content") and result["candidates"][0]["content"].get("parts"):
            # The result.candidates[0].content.parts[0].text is a stringified JSON
            json_string = result["candidates"][0]["content"]["parts"][0]["text"]
            return json.loads(json_string)
        else:
            return {"error": "Unexpected Gemini API response structure."}
    except requests.exceptions.RequestException as e:
        print(f"Gemini API request failed: {e}")
        return {"error": f"Gemini API request failed: {e}"}
    except json.JSONDecodeError as e:
        print(f"Failed to decode Gemini API response JSON: {e}")
        print(f"Raw Gemini response: {response.text}")
        return {"error": "Failed to parse Gemini API response."}
    except Exception as e:
        print(f"An unexpected error occurred during Gemini API call: {e}")
        return {"error": f"An unexpected error occurred: {e}"}


def analyze_document_task(url_hash, url):
    """
    Background task to perform the full document analysis.
    This function runs in a separate thread.
    """
    job_statuses[url_hash] = {"status": "scraping", "progress": 10}
    try:
        # 1. Web Scraping
        document_text = get_document_text(url)
        if not document_text:
            job_statuses[url_hash] = {"status": "failed", "error": "Failed to scrape document content."}
            return

        # Limit document text to prevent excessively large prompts (Gemini 2.0 Flash context window)
        # This is a heuristic; adjust as needed based on model limits and typical document sizes.
        MAX_TEXT_LENGTH = 15000  # Characters
        if len(document_text) > MAX_TEXT_LENGTH:
            document_text = document_text[:MAX_TEXT_LENGTH] + "\n... (document truncated)"

        job_statuses[url_hash] = {"status": "analyzing_summary", "progress": 30}
        # 2. Call Gemini API for various analyses
        summary_res = call_gemini_api(document_text, "summary")
        if "error" in summary_res:
            job_statuses[url_hash] = {"status": "failed", "error": summary_res["error"]}
            return

        job_statuses[url_hash] = {"status": "analyzing_data_collection", "progress": 50}
        data_collection_res = call_gemini_api(document_text, "data_collection")
        if "error" in data_collection_res:
            job_statuses[url_hash] = {"status": "failed", "error": data_collection_res["error"]}
            return

        job_statuses[url_hash] = {"status": "analyzing_data_sharing", "progress": 70}
        data_sharing_res = call_gemini_api(document_text, "data_sharing")
        if "error" in data_sharing_res:
            job_statuses[url_hash] = {"status": "failed", "error": data_sharing_res["error"]}
            return

        job_statuses[url_hash] = {"status": "analyzing_suspicious_terms", "progress": 90}
        suspicious_terms_res = call_gemini_api(document_text, "suspicious_terms")
        if "error" in suspicious_terms_res:
            job_statuses[url_hash] = {"status": "failed", "error": suspicious_terms_res["error"]}
            return

        # 3. Combine results
        combined_analysis = {
            "url": url,
            "summary": summary_res.get("summary", "No summary available."),
            "data_collection": data_collection_res,
            "data_sharing": data_sharing_res,
            "suspicious_terms": suspicious_terms_res,
            "timestamp": time.time()
        }

        # 4. Cache results
        cache_path = os.path.join(CACHE_DIR, url_hash)
        os.makedirs(cache_path, exist_ok=True)
        with open(os.path.join(cache_path, 'analysis.json'), 'w', encoding='utf-8') as f:
            json.dump(combined_analysis, f, ensure_ascii=False, indent=4)
        with open(os.path.join(cache_path, 'raw.txt'), 'w', encoding='utf-8') as f:
             f.write(document_text) # Store raw text, not raw HTML

        job_statuses[url_hash] = {"status": "completed", "result": combined_analysis, "progress": 100}

    except Exception as e:
        print(f"Error in analyze_document_task for {url}: {e}")
        job_statuses[url_hash] = {"status": "failed", "error": str(e)}


@app.route('/')
def index():
    """Renders the main frontend HTML page."""
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze_url():
    """
    Endpoint to initiate document analysis.
    Checks cache first, then starts an asynchronous task if not cached.
    """
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({"error": "URL is required."}), 400

    # Basic URL validation
    if not url.startswith('http://') and not url.startswith('https://'):
        return jsonify({"error": "Invalid URL format. Must start with http:// or https://."}), 400

    url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()
    cache_file_path = os.path.join(CACHE_DIR, url_hash, 'analysis.json')

    # Check cache
    if os.path.exists(cache_file_path):
        try:
            with open(cache_file_path, 'r', encoding='utf-8') as f:
                cached_analysis = json.load(f)
            # You could add cache invalidation logic here based on timestamp
            # For now, it's permanent until explicitly told otherwise.
            print(f"Serving cached analysis for {url}")
            job_statuses[url_hash] = {"status": "completed", "result": cached_analysis, "progress": 100}
            return jsonify({"job_id": url_hash, "status": "completed", "result": cached_analysis})
        except json.JSONDecodeError as e:
            print(f"Error reading cached JSON for {url_hash}: {e}. Re-analyzing.")
            # If cache is corrupted, proceed to re-analyze
            pass

    # If not cached, start a background task
    print(f"Starting new analysis for {url} (Job ID: {url_hash})")
    job_statuses[url_hash] = {"status": "started", "progress": 0}
    executor.submit(analyze_document_task, url_hash, url) # Run task in a separate thread

    return jsonify({"job_id": url_hash, "status": "processing"}), 202


@app.route('/status/<job_id>', methods=['GET'])
def get_job_status(job_id):
    """
    Endpoint to check the status of an analysis job.
    """
    status_info = job_statuses.get(job_id)
    if status_info:
        # Don't send the full result in the status check, only status and progress
        response_data = {"job_id": job_id, "status": status_info["status"], "progress": status_info.get("progress", 0)}
        if "error" in status_info:
            response_data["error"] = status_info["error"]
        return jsonify(response_data)
    else:
        return jsonify({"error": "Job ID not found or expired."}), 404


@app.route('/result/<job_id>', methods=['GET'])
def get_job_result(job_id):
    """
    Endpoint to retrieve the full analysis result once completed.
    """
    status_info = job_statuses.get(job_id)
    if not status_info:
        return jsonify({"error": "Job ID not found or expired."}), 404

    if status_info["status"] == "completed":
        # The result is already in job_statuses from analyze_document_task
        return jsonify(status_info["result"])
    elif status_info["status"] == "failed":
        return jsonify({"error": status_info.get("error", "Analysis failed.")}), 500
    else:
        return jsonify({"status": "processing", "message": "Analysis is still in progress."}), 409


if __name__ == '__main__':
    # For local development, you can run: python app.py
    # In a production Gunicorn/WSGI environment, the server will handle this.
    app.run(debug=True, host='127.0.0.1', port=5000)

