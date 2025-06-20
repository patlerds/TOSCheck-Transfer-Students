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
import shutil # For deleting directories
from packaging.version import parse as parse_version # Import for robust version parsing
import urllib.parse # For URL parsing
import ipaddress # For IP address validation
import socket # For DNS resolution

# Load environment variables from .env file (for API key during local development)
load_dotenv()

app = Flask(__name__)

# Configuration
CACHE_DIR = './cache/TOSCheck'
os.makedirs(CACHE_DIR, exist_ok=True) # Ensure cache directory exists

# --- Versioning Configuration ---
VERSION_FILE = 'version.txt'
# Increment version for new data structure
CURRENT_APP_VERSION = "1.0.1" # Updated version to reflect new comprehensive analysis schema

def load_current_app_version():
    """Reads the current application version from version.txt."""
    global CURRENT_APP_VERSION
    try:
        with open(VERSION_FILE, 'r') as f:
            version_from_file = f.read().strip()
            # Validate version format if desired, but parse_version will handle many formats
            CURRENT_APP_VERSION = version_from_file
        print(f"Application version loaded: {CURRENT_APP_VERSION}")
    except FileNotFoundError:
        print(f"Warning: {VERSION_FILE} not found. Using default version {CURRENT_APP_VERSION}.")
    except Exception as e:
        print(f"Error loading version from {VERSION_FILE}: {e}. Using default version {CURRENT_APP_VERSION}.")

load_current_app_version()

# --- End Versioning Configuration ---

# Gemini API Key - Prioritize environment variables.
# For Canvas environment, an empty string will allow the platform to inject it via __api_key__.
# This variable acts as a fallback/storage for explicit setting.
GEMINI_API_KEY_EXPLICIT = os.getenv("GEMINI_API_KEY")

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent"

# In-memory dictionary to track job statuses for asynchronous tasks
# In a real-world scenario with multiple Flask workers, this would need a shared, persistent store (e.g., Redis)
job_statuses = {}

# Thread pool for running blocking I/O tasks like scraping and LLM calls
# This helps prevent blocking the main Flask thread when using a non-async Flask setup.
executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)

# --- SSRF Prevention Configuration ---
# Define private IP ranges (IPv4 and IPv6) and known metadata service IPs
# These are CIDR notations
FORBIDDEN_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),       # Private A
    ipaddress.ip_network('172.16.0.0/12'),    # Private B
    ipaddress.ip_network('192.168.0.0/16'),   # Private C
    ipaddress.ip_network('127.0.0.0/8'),      # Loopback
    ipaddress.ip_network('169.254.0.0/16'),   # Link-local
    ipaddress.ip_network('0.0.0.0/8'),        # Current network (can include local, default routes)
    ipaddress.ip_network('::1/128'),          # IPv6 Loopback
    ipaddress.ip_network('fc00::/7'),         # IPv6 Unique Local Address
    ipaddress.ip_network('fe80::/10')         # IPv6 Link-local Address
]

# Specific cloud metadata service IP (AWS, GCP, Azure common)
FORBIDDEN_HOSTNAMES = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "169.254.169.254" # AWS EC2 Metadata service (also used by others)
]

def is_safe_url(url):
    """
    Checks if a URL points to a public, non-reserved IP address or hostname.
    Prevents SSRF by blocking access to private networks and metadata services.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname

        if not hostname:
            return False # No hostname, can't validate

        # Check against forbidden hostnames directly
        if hostname.lower() in FORBIDDEN_HOSTNAMES:
            return False

        # Resolve hostname to IP addresses
        try:
            # getaddrinfo returns a list of 5-tuples: (family, socktype, proto, canonname, sockaddr)
            # sockaddr is (ip_address, port) for IPv4 or (ip_address, port, flowinfo, scopeid) for IPv6
            # We only care about the IP address.
            ip_addresses = [info[4][0] for info in socket.getaddrinfo(hostname, None)]
        except socket.gaierror:
            # Hostname could not be resolved, treat as unsafe or invalid
            print(f"Warning: Could not resolve hostname for {hostname}")
            return False

        for ip_str in ip_addresses:
            try:
                ip_addr = ipaddress.ip_address(ip_str)
                for forbidden_range in FORBIDDEN_IP_RANGES:
                    if ip_addr in forbidden_range:
                        print(f"SSRF Alert: Blocked access to private IP range {ip_str} for URL {url}")
                        return False
                # Also explicitly check for the common metadata service IP by its address form
                if ip_str == "169.254.169.254":
                    print(f"SSRF Alert: Blocked access to metadata service IP {ip_str} for URL {url}")
                    return False
            except ValueError:
                # Not a valid IP address, skip
                continue

        return True

    except Exception as e:
        print(f"Error during URL safety check for {url}: {e}")
        return False

# --- End SSRF Prevention Configuration ---


def get_gemini_api_key():
    """
    Retrieves the Gemini API key.
    Prioritizes __api_key__ injected by Canvas, then GEMINI_API_KEY_EXPLICIT (from .env or env var).
    """
    # For Canvas, the __api_key__ global variable is injected
    canvas_key = os.environ.get("__api_key__")
    if canvas_key:
        return canvas_key
    
    # Fallback to explicit env var set in .env or system env
    if GEMINI_API_KEY_EXPLICIT:
        return GEMINI_API_KEY_EXPLICIT
    
    if not GEMINI_API_KEY_EXPLICIT: # If not found in environment variableAdd commentMore actions
        # A list of possible locations for the gemini.txt file
        key_locations = [
                os.path.join(os.path.dirname(__file__), '..', 'gemini.txt'),
                '/home/nish/web/gemini.txt', # This path is explicitly checked
        ]

            # Loop through the locations and use the first key found
        for file_path in key_locations:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    GEMINI_API_KEY = f.read().strip()
                    return GEMINI_API_KEY
                if GEMINI_API_KEY:
                    break # Exit loop once key is found
    
    print("Warning: Gemini API Key not found. Please set GEMINI_API_KEY environment variable or ensure it's injected by Canvas.")
    return None # Explicitly return None if no key is found


def get_document_text(url):
    """
    Fetches HTML content from a given URL and extracts the main text content.
    Includes more comprehensive headers to mimic a browser.
    Ensures UTF-8 decoding.
    Returns a tuple: (text_content, page_title)
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1', # Do Not Track request header
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        # 'Referer': 'https://www.google.com/', # Can be added if needed, sometimes helps
    }
    page_title = "Untitled Document"
    try:
        response = requests.get(url, headers=headers, timeout=15) # Increased timeout
        response.raise_for_status()

        # Explicitly set encoding to UTF-8 if it's not already, or if it's detected incorrectly
        response.encoding = 'utf-8' # Force UTF-8 decoding

        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract title
        if soup.title and soup.title.string:
            page_title = soup.title.string.strip()
        elif soup.find('h1') and soup.find('h1').string:
            page_title = soup.find('h1').string.strip()


        # Attempt to extract main content. This is a heuristic and might need refinement
        # for different website structures.
        main_content = soup.find('article') or soup.find('main') or soup.find('body')

        if not main_content:
            return "Could not extract main content from the page.", page_title

        # Extract text from paragraphs, headings, and list items
        paragraphs = main_content.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li'])
        text_content = "\n".join([elem.get_text(separator=" ", strip=True) for elem in paragraphs])

        # Basic sanitization to remove excessive whitespace
        text_content = ' '.join(text_content.split())
        return text_content, page_title

    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        return None, page_title # Return page_title even on error if available
    except Exception as e:
        print(f"Error processing content for {url}: {e}")
        return None, page_title # Return page_title even on error if available


def call_gemini_api(document_text, prompt_type):
    """
    Calls the Gemini API with the given document text and a specific prompt type.
    """
    api_key = get_gemini_api_key()
    if not api_key:
        print("Gemini API Key not found. Please set GEMINI_API_KEY or ensure it's injected by Canvas.")
        return {"error": "Gemini API Key not configured."}

    # Define prompts and schemas based on the design document
    # Using a single comprehensive analysis prompt type
    prompts = {
        "comprehensive_analysis": {
            "text": """Analyze the following legal document (e.g., Privacy Policy, Terms of Service) and extract the following information. For each attribute, provide the requested details and a direct quote (citation) from the document that supports your finding. If an attribute or sub-attribute is not explicitly mentioned or applicable, state 'N/A' for strings/arrays, 'false' for booleans, or "Not explicitly stated" for dates. Use **bold** for key terms and *italics* for emphasis where appropriate in descriptions. Use markdown lists for multiple points.

1.  **Product/Service Coverage (`product_coverage`)**:
    * List the specific products, services, or platforms this document applies to.
    * Format: Array of strings.

2.  **Document Last Update Date (`last_update_date`)**:
    * The most recent date on which the document was updated or came into effect.
    * Format: String in 'YYYY-MM-DD' format. If not explicitly stated, use "Not explicitly stated".

3.  **Notification & Liability Before Service Action (`notification_liability_before_action`)**:
    * `commitment_exists`: Boolean (true/false) - Is there a commitment to notify the user or limit liability before significant service actions (e.g., suspension, major changes)?
    * `details`: Explanation of the commitment.
    * `citation`: Direct quote.

4.  **Prohibited Actions (User Conduct) (`prohibited_actions`)**:
    * List activities forbidden for users.
    * Format: Array of objects, each with `action` (string) and `citation` (string).

5.  **Reasons for Service Termination/Suspension (`termination_reasons`)**:
    * List conditions under which the service can terminate/suspend a user's account.
    * Format: Array of objects, each with `reason` (string) and `citation` (string).

6.  **Data Protection Measures (`data_protections`)**:
    * Information on technical/organizational data protection measures (e.g., Encryption, Anonymization, Access Controls).
    * Format: Array of objects, each with `protection_type` (string), `status` (string: "Applies", "Not Explicitly Mentioned"), `details` (string), and `citation` (string).

7.  **Privacy Protections & User Rights (`privacy_protections_user_rights`)**:
    * Details about user privacy rights (e.g., Right to Access, Deletion, Opt-out of Marketing, Data Portability).
    * Format: Array of objects, each with `right_type` (string), `status` (string: "Applies", "Not Explicitly Mentioned"), `details` (string), and `citation` (string).

8.  **Dispute Resolution & Governing Law (`dispute_resolution`)**:
    * `method`: How disputes are resolved (e.g., "Binding Arbitration", "Litigation").
    * `governing_law`: Applicable jurisdiction/law.
    * `details`: Explanation of the process.
    * `citation`: Direct quote.

9.  **Limitation of Liability (`limitation_of_liability`)**:
    * `exists`: Boolean (true/false) - Is there a clause limiting service provider's liability?
    * `summary`: Concise summary of the limitation.
    * `citation`: Direct quote.

10. **Intellectual Property Rights (`intellectual_property`)**:
    * `ownership_of_service`: Who owns the service's IP.
    * `user_content_rights`: How user-generated content IP is handled (e.g., user retains ownership, grants license).
    * `citation`: Direct quote covering both aspects.

11. **Changes to Terms (`changes_to_terms`)**:
    * `method`: How terms can be modified (e.g., "Unilateral changes with notice").
    * `notification_period`: How many days notice, if any.
    * `user_consent_required`: Boolean (true/false) - Is user consent required for changes?
    * `citation`: Direct quote.

Document Text:
""",
            "schema": {
                "type": "OBJECT",
                "properties": {
                    "product_coverage": {"type": "ARRAY", "items": {"type": "STRING"}},
                    "last_update_date": {"type": "STRING"},
                    "notification_liability_before_action": {
                        "type": "OBJECT",
                        "properties": {
                            "commitment_exists": {"type": "BOOLEAN"},
                            "details": {"type": "STRING"},
                            "citation": {"type": "STRING"}
                        },
                        "required": ["commitment_exists", "details", "citation"]
                    },
                    "prohibited_actions": {
                        "type": "ARRAY",
                        "items": {
                            "type": "OBJECT",
                            "properties": {
                                "action": {"type": "STRING"},
                                "citation": {"type": "STRING"}
                            },
                            "required": ["action", "citation"]
                        }
                    },
                    "termination_reasons": {
                        "type": "ARRAY",
                        "items": {
                            "type": "OBJECT",
                            "properties": {
                                "reason": {"type": "STRING"},
                                "citation": {"type": "STRING"}
                            },
                            "required": ["reason", "citation"]
                        }
                    },
                    "data_protections": {
                        "type": "ARRAY",
                        "items": {
                            "type": "OBJECT",
                            "properties": {
                                "protection_type": {"type": "STRING"},
                                "status": {"type": "STRING"},
                                "details": {"type": "STRING"},
                                "citation": {"type": "STRING"}
                            },
                            "required": ["protection_type", "status", "details", "citation"]
                        }
                    },
                    "privacy_protections_user_rights": {
                        "type": "ARRAY",
                        "items": {
                            "type": "OBJECT",
                            "properties": {
                                "right_type": {"type": "STRING"},
                                "status": {"type": "STRING"},
                                "details": {"type": "STRING"},
                                "citation": {"type": "STRING"}
                            },
                            "required": ["right_type", "status", "details", "citation"]
                        }
                    },
                    "dispute_resolution": {
                        "type": "OBJECT",
                        "properties": {
                            "method": {"type": "STRING"},
                            "governing_law": {"type": "STRING"},
                            "details": {"type": "STRING"},
                            "citation": {"type": "STRING"}
                        },
                        "required": ["method", "governing_law", "details", "citation"]
                    },
                    "limitation_of_liability": {
                        "type": "OBJECT",
                        "properties": {
                            "exists": {"type": "BOOLEAN"},
                            "summary": {"type": "STRING"},
                            "citation": {"type": "STRING"}
                        },
                        "required": ["exists", "summary", "citation"]
                    },
                    "intellectual_property": {
                        "type": "OBJECT",
                        "properties": {
                            "ownership_of_service": {"type": "STRING"},
                            "user_content_rights": {"type": "STRING"},
                            "citation": {"type": "STRING"}
                        },
                        "required": ["ownership_of_service", "user_content_rights", "citation"]
                    },
                    "changes_to_terms": {
                        "type": "OBJECT",
                        "properties": {
                            "method": {"type": "STRING"},
                            "notification_period": {"type": "STRING"}, # Changed to string as "30 days" or "N/A"
                            "user_consent_required": {"type": "BOOLEAN"},
                            "citation": {"type": "STRING"}
                        },
                        "required": ["method", "notification_period", "user_consent_required", "citation"]
                    }
                },
                "required": [
                    "product_coverage", "last_update_date", "notification_liability_before_action",
                    "prohibited_actions", "termination_reasons", "data_protections",
                    "privacy_protections_user_rights", "dispute_resolution", "limitation_of_liability",
                    "intellectual_property", "changes_to_terms"
                ]
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
        # Updated to unpack raw_html_content
        document_text, page_title, raw_html_content = get_document_text(url)
        
        # Check if scraping failed or returned empty content/html
        if not document_text or not raw_html_content:
            job_statuses[url_hash] = {"status": "failed", "error": "Failed to scrape document content or raw HTML."}
            return

        # Limit document text to prevent excessively large prompts (Gemini 2.0 Flash context window)
        # This is a heuristic; adjust as needed based on model limits and typical document sizes.
        MAX_TEXT_LENGTH = 15000  # Characters
        if len(document_text) > MAX_TEXT_LENGTH:
            document_text = document_text[:MAX_TEXT_LENGTH] + "\n... (document truncated)"

        job_statuses[url_hash] = {"status": "analyzing", "progress": 30}
        # 2. Call Gemini API for comprehensive analysis
        full_analysis_res = call_gemini_api(document_text, "comprehensive_analysis")
        if "error" in full_analysis_res:
            job_statuses[url_hash] = {"status": "failed", "error": full_analysis_res["error"]}
            return

        # 3. Combine results - directly use the full_analysis_res
        combined_analysis = {
            "version": CURRENT_APP_VERSION, # Add current app version to cache
            "url": url,
            "title": page_title, # Store the page title
            "full_analysis": full_analysis_res, # Store the comprehensive result
            "timestamp": time.time()
        }

        # 4. Cache results
        cache_path = os.path.join(CACHE_DIR, url_hash)
        os.makedirs(cache_path, exist_ok=True)

        html_file_path = os.path.join(cache_path, 'html.txt')
        raw_text_file_path = os.path.join(cache_path, 'raw.txt')
        analysis_json_file_path = os.path.join(cache_path, 'analysis.json')

        with open(analysis_json_file_path, 'w', encoding='utf-8') as f:
            json.dump(combined_analysis, f, ensure_ascii=False, indent=4)
        with open(raw_text_file_path, 'w', encoding='utf-8') as f:
            f.write(document_text)
        with open(html_file_path, 'w', encoding='utf-8') as f: # Save raw HTML content
            f.write(raw_html_content)

        # 5. Check file sizes for minimum content (1KB = 1024 bytes)
        # Assuming that small file sizes indicate a failed download or poor content extraction
        if os.path.getsize(html_file_path) < 1024 or os.path.getsize(raw_text_file_path) < 1024:
            error_message = "Downloaded HTML or extracted text content is too small (less than 1KB), indicating a potential scraping or extraction failure."
            print(f"Warning: {error_message} for URL: {url} (Hash: {url_hash})")
            job_statuses[url_hash] = {"status": "failed", "error": error_message}
            return

        job_statuses[url_hash] = {"status": "completed", "result": combined_analysis, "progress": 100}

    except Exception as e:
        print(f"Error in analyze_document_task for {url}: {e}")
        job_statuses[url_hash] = {"status": "failed", "error": str(e)}


@app.route('/')
def index():
    """Renders the main frontend HTML page."""
    load_current_app_version()
    return render_template('index.html', app_version=CURRENT_APP_VERSION)

    
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

    # --- SSRF Prevention: Validate URL safety before proceeding ---
    if not is_safe_url(url):
        return jsonify({"error": "Provided URL is not allowed. Potential security risk."}), 403
    # --- END SSRF Prevention ---

    url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()
    cache_dir_path = os.path.join(CACHE_DIR, url_hash)
    cache_file_path = os.path.join(cache_dir_path, 'analysis.json')

    # Check cache
    if os.path.exists(cache_file_path):
        try:
            with open(cache_file_path, 'r', encoding='utf-8') as f:
                cached_analysis = json.load(f)

            cached_version_str = cached_analysis.get('version', '0.0.0') # Default to '0.0.0' if version not found
            
            # Use packaging.version for robust comparison
            if parse_version(cached_version_str) < parse_version(CURRENT_APP_VERSION):
                print(f"Cached version {cached_version_str} is older than current version {CURRENT_APP_VERSION} for {url}. Deleting cache and re-analyzing.")
                shutil.rmtree(cache_dir_path) # Delete old cache directory
                # Proceed to re-analyze below
            else:
                print(f"Serving cached analysis (version {cached_version_str}) for {url}")
                job_statuses[url_hash] = {"status": "completed", "result": cached_analysis, "progress": 100}
                return jsonify({"job_id": url_hash, "status": "completed", "result": cached_analysis})

        except json.JSONDecodeError as e:
            print(f"Error reading cached JSON for {url_hash}: {e}. Cache might be corrupted. Re-analyzing.")
            if os.path.exists(cache_dir_path):
                shutil.rmtree(cache_dir_path) # Delete corrupted cache
            # Proceed to re-analyze below
        except Exception as e:
            print(f"An unexpected error occurred during cache check for {url_hash}: {e}. Re-analyzing.")
            if os.path.exists(cache_dir_path):
                shutil.rmtree(cache_dir_path) # Delete potentially problematic cache
            # Proceed to re-analyze below

    # If not cached, or cache was old/corrupted, start a background task
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

@app.route('/recent_analyses', methods=['GET'])
def get_recent_analyses():
    """
    Endpoint to retrieve a list of recent analyses from the cache.
    Returns up to 5 most recent analyses with their URL and title.
    """
    recent_items = []
    cache_entries = []

    for entry_name in os.listdir(CACHE_DIR):
        entry_path = os.path.join(CACHE_DIR, entry_name)
        analysis_file = os.path.join(entry_path, 'analysis.json')
        
        if os.path.isdir(entry_path) and os.path.exists(analysis_file):
            try:
                with open(analysis_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Ensure essential keys exist
                    # For recent analyses, we only need URL and Title, which are top-level.
                    if 'url' in data and 'timestamp' in data:
                        cache_entry = {
                            "url": data['url'],
                            "title": data.get('title', 'Untitled Document'), # Use stored title, fallback if not present
                            "timestamp": data['timestamp']
                        }
                        cache_entries.append(cache_entry)
            except json.JSONDecodeError:
                print(f"Warning: Corrupted JSON cache file: {analysis_file}")
            except Exception as e:
                print(f"Error reading cache entry {analysis_file}: {e}")

    # Sort by timestamp, most recent first
    cache_entries.sort(key=lambda x: x['timestamp'], reverse=True)

    # Get top 5 (or fewer if less than 5)
    recent_items = cache_entries[:5]

    return jsonify(recent_items)


if __name__ == '__main__':
    # For local development, you can run: python app.py
    # In a production Gunicorn/WSGI environment, the server will handle this.
    app.run(debug=True, host='127.0.0.1', port=5000)

