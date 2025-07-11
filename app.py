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
import concurrent.futures # Correct import for ThreadPoolExecutor
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
# Updated version to reflect new comprehensive analysis schema + raw text in cache
# Further incremented version for 10-word and 1-paragraph summaries
# Incrementing again for 'user_concerns' and 'key_points' in simple mode
CURRENT_APP_VERSION = "1.0.1.5"

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
# CORRECTED: Changed ThreadPoolPoolExecutor to ThreadPoolExecutor
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

    if not GEMINI_API_KEY_EXPLICIT:
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

3.  **Ten Word Summary (`ten_word_summary`)**:
    * A very concise summary, exactly ten words long, capturing the essence of the document.
    * Format: String.

4.  **One Paragraph Summary (`one_paragraph_summary`)**:
    * A comprehensive summary of the entire document, condensed into a single paragraph (approximately 5-7 sentences). Focus on key takeaways, implications for the user, and significant clauses.
    * Format: String.

5.  **Key Points with Citations (`key_points`)**:
    * Extract 3-5 most important key points from the document, relevant to a general user. Each point must include a direct citation from the document.
    * Format: Array of objects, each with `point` (string) and `citation` (string).

6.  **Things User Should Be Worried About (`user_concerns`)**:
    * List potential risks, unfavorable clauses, or significant concerns for the user, based on the document. Each concern must include a direct citation from the document. If no specific concerns are found, state 'N/A' for point and citation.
    * Format: Array of objects, each with `point` (string) and `citation` (string).

7.  **Notification & Liability Before Service Action (`notification_liability_before_action`)**:
    * `commitment_exists`: Boolean (true/false) - Is there a commitment to notify the user or limit liability before significant service actions (e.g., suspension, major changes)?
    * `details`: Explanation of the commitment.
    * `citation`: Direct quote.

8.  **Prohibited Actions (User Conduct) (`prohibited_actions`)**:
    * List activities forbidden for users.
    * Format: Array of objects, each with `action` (string) and `citation` (string).

9.  **Reasons for Service Termination/Suspension (`termination_reasons`)**:
    * List conditions under which the service can terminate/suspend a user's account.
    * Format: Array of objects, each with `reason` (string) and `citation` (string).

10. **Data Protection Measures (`data_protections`)**:
    * Information on technical/organizational data protection measures (e.g., Encryption, Anonymization, Access Controls).
    * Format: Array of objects, each with `protection_type` (string), `status` (string: "Applies", "Not Explicitly Mentioned"), `details` (string), and `citation` (string).

11. **Privacy Protections & User Rights (`privacy_protections_user_rights`)**:
    * Details about user privacy rights (e.g., Right to Access, Deletion, Opt-out of Marketing, Data Portability).
    * Format: Array of objects, each with `right_type` (string), `status` (string: "Applies", "Not Explicitly Mentioned"), `details` (string), and `citation` (string).

12. **Dispute Resolution & Governing Law (`dispute_resolution`)**:
    * `method`: How disputes are resolved (e.g., "Binding Arbitration", "Litigation").
    * `governing_law`: Applicable jurisdiction/law.
    * `details`: Explanation of the process.
    * `citation`: Direct quote.

13. **Limitation of Liability (`limitation_of_liability`)**:
    * `exists`: Boolean (true/false) - Is there a clause limiting service provider's liability?
    * `summary`: Concise summary of the limitation.
    * `citation`: Direct quote.

14. **Intellectual Property Rights (`intellectual_property`)**:
    * `ownership_of_service`: Who owns the service's IP.
    * `user_content_rights`: How user-generated content IP is handled (e.g., user retains ownership, grants license).
    * `citation`: Direct quote covering both aspects.

15. **Changes to Terms (`changes_to_terms`)**:
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
                    "ten_word_summary": {"type": "STRING"},          # New summary field
                    "one_paragraph_summary": {"type": "STRING"},     # New summary field
                    "key_points": {                                  # New key points field
                        "type": "ARRAY",
                        "items": {
                            "type": "OBJECT",
                            "properties": {
                                "point": {"type": "STRING"},
                                "citation": {"type": "STRING"}
                            },
                            "required": ["point", "citation"]
                        }
                    },
                    "user_concerns": {                               # New user concerns field
                        "type": "ARRAY",
                        "items": {
                            "type": "OBJECT",
                            "properties": {
                                "point": {"type": "STRING"},
                                "citation": {"type": "STRING"}
                            },
                            "required": ["point", "citation"]
                        }
                    },
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
                    "product_coverage", "last_update_date", "ten_word_summary", "one_paragraph_summary",
                    "key_points", "user_concerns", # Added new fields to required
                    "notification_liability_before_action",
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

def get_document_text(url):
    """
    Fetches HTML content from a given URL and extracts the main text content.
    Includes more comprehensive headers to mimic a browser.
    Ensures UTF-8 decoding.
    Returns a tuple: (text_content, page_title, raw_html_content)
    """
    if not is_safe_url(url):
        print(f"SSRF Prevention: Attempted to scrape unsafe URL: {url}")
        return "", "Unsafe URL", "" # Return empty strings for content and html, and a specific title

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
    raw_html_content = "" # Initialize raw_html_content

    try:
        response = requests.get(url, headers=headers, timeout=15) # Increased timeout
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        # Store raw HTML content
        raw_html_content = response.text

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
            return "Could not extract main content from the page.", page_title, raw_html_content

        # Extract text from paragraphs, headings, and list items
        paragraphs = main_content.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li'])
        text_content = "\n".join([elem.get_text(separator=" ", strip=True) for elem in paragraphs])

        # Basic sanitization to remove excessive whitespace
        text_content = ' '.join(text_content.split())
        return text_content, page_title, raw_html_content

    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        # Return error message for text_content, but keep title and any raw HTML fetched before error
        return f"Error fetching URL: {e}", page_title, raw_html_content
    except Exception as e:
        print(f"Error processing content for {url}: {e}")
        # Return error message for text_content, but keep title and any raw HTML fetched before error
        return f"Error processing content: {e}", page_title, raw_html_content

def analyze_document_task(url_hash, url):
    """
    Background task to perform the full document analysis.
    This function runs in a separate thread.
    It now creates directories and saves HTML, MD, and JSON files even if steps fail
    to allow for easier inspection of failure points.
    """
    # Initialize variables that will hold the results or error messages
    document_text = ""
    page_title = "Untitled Document"
    raw_html_content = ""
    full_analysis_res = {"error": "Analysis not yet performed or failed early."} # Default error object for JSON
    overall_status = "failed" # Assume failure until proven otherwise
    final_error_message = None
    document_raw_text_content = "" # Initialize variable to hold raw text content for citation checking

    # Ensure cache directory exists and define file paths early
    cache_path = os.path.join(CACHE_DIR, url_hash)
    os.makedirs(cache_path, exist_ok=True)
    html_file_path = os.path.join(cache_path, 'html.txt')
    raw_text_file_path = os.path.join(cache_path, 'raw.txt')
    analysis_json_file_path = os.path.join(cache_path, 'analysis.json')

    job_statuses[url_hash] = {"status": "scraping", "progress": 10}

    print(f"Starting download and scraping for {url}")

    try:
        # 1. Web Scraping and Text Extraction
        scraped_text, scraped_title, scraped_html = get_document_text(url)

        # Always store the raw HTML content, even if it's an error message or empty string
        raw_html_content = scraped_html
        with open(html_file_path, 'w', encoding='utf-8') as f:
            f.write(raw_html_content)

        if not scraped_text or "Error fetching URL" in scraped_text or "Could not extract main content" in scraped_text or "Unsafe URL" in scraped_text:
            final_error_message = scraped_text if scraped_text else "Failed to extract main text content from the page."
            document_text = final_error_message # Store error message in document_text
        else:
            document_text = scraped_text
            page_title = scraped_title

            # Limit document text to prevent excessively large prompts (Gemini 2.0 Flash context window)
            MAX_TEXT_LENGTH = 15000  # Characters
            if len(document_text) > MAX_TEXT_LENGTH:
                document_text = document_text[:MAX_TEXT_LENGTH] + "\n... (document truncated)"

        # Read the raw text for citation later (this is the potentially truncated text for LLM)
        # Always write raw.txt, even if it contains an error message or is small
        with open(raw_text_file_path, 'w', encoding='utf-8') as f:
            f.write(document_text)

        # Store the full extracted text for citation validation (this should be the non-truncated one ideally,
        # but for consistency with what was passed to LLM, we use the potentially truncated one here).
        # A more robust solution might store both original and truncated.
        document_raw_text_content = document_text


        # 2. Check file sizes for minimum content (1KB = 1024 bytes)
        # This check determines if the scraping/extraction was "successful enough" for LLM
        html_file_size_ok = os.path.exists(html_file_path) and os.path.getsize(html_file_path) >= 1024
        raw_text_file_size_ok = os.path.exists(raw_text_file_path) and os.path.getsize(raw_text_file_path) >= 1024

        # Determine if we should proceed with LLM analysis
        proceed_with_llm = html_file_size_ok and raw_text_file_size_ok and document_text and not ("Error fetching URL" in document_text or "Could not extract main content" in document_text or "Unsafe URL" in document_text)

        if not proceed_with_llm:
            error_details = []
            if not html_file_size_ok:
                error_details.append(f"html.txt ({os.path.getsize(html_file_path) if os.path.exists(html_file_path) else 0} bytes) is too small")
            if not raw_text_file_size_ok:
                error_details.append(f"raw.txt ({os.path.getsize(raw_text_file_path) if os.path.exists(raw_text_file_path) else 0} bytes) is too small")
            if not document_text:
                error_details.append("extracted document text is empty")
            if "Error fetching URL" in document_text or "Could not extract main content" in document_text or "Unsafe URL" in document_text:
                error_details.append(f"scraping/extraction error: {document_text}")

            final_error_message = "Scraping or text extraction considered failed for LLM analysis: " + "; ".join(error_details)
            print(f"Warning: {final_error_message} for URL: {url} (Hash: {url_hash})")
            full_analysis_res["error"] = final_error_message # Update default error object
        else:
            # Only call LLM if scraping/extraction was successful enough
            job_statuses[url_hash] = {"status": "analyzing", "progress": 30}
            gemini_result = call_gemini_api(document_text, "comprehensive_analysis")

            if "error" in gemini_result:
                final_error_message = gemini_result["error"]
                full_analysis_res["error"] = final_error_message # Update default error object
            else:
                full_analysis_res = gemini_result
                overall_status = "completed" # Analysis successfully completed


    except Exception as e:
        final_error_message = f"An unexpected error occurred during analysis: {str(e)}"
        print(f"Error in analyze_document_task for {url}: {final_error_message}")
        full_analysis_res["error"] = final_error_message # Ensure error is in the JSON payload


    finally:
        # 3. Combine results - always create combined_analysis to be saved
        combined_analysis = {
            "version": CURRENT_APP_VERSION,
            "url": url,
            "title": page_title,
            "full_analysis": full_analysis_res, # Will contain analysis or error object
            "document_raw_text": document_raw_text_content, # Include the raw text here
            "timestamp": time.time()
        }

        # Add overall error message to combined_analysis if it exists
        if final_error_message:
            combined_analysis["error_message_overall"] = final_error_message # Use a distinct key

        # Always write analysis.json
        try:
            with open(analysis_json_file_path, 'w', encoding='utf-8') as f:
                json.dump(combined_analysis, f, ensure_ascii=False, indent=4)
        except Exception as write_err:
            print(f"Error writing analysis.json on cleanup for {url_hash}: {write_err}")
            # If writing JSON itself fails, report this as the ultimate failure
            final_error_message = f"Critical: Failed to save analysis JSON: {str(write_err)}"
            overall_status = "failed"
            combined_analysis["error_message_overall"] = final_error_message


        # Final status update in job_statuses
        job_statuses[url_hash] = {
            "status": overall_status,
            "result": combined_analysis, # Store the combined analysis (which includes potential errors)
            "progress": 100 if overall_status == "completed" else job_statuses[url_hash].get("progress", 0) # Retain progress if it failed mid-way
        }
        if overall_status == "failed" and final_error_message:
            job_statuses[url_hash]["error"] = final_error_message


@app.route('/')
def index():
    """Renders the main frontend HTML page."""
    return render_template('index.html', app_version=CURRENT_APP_VERSION)

# New route for the search page
@app.route('/search')
def search_page():
    """Renders the search cached websites HTML page."""
    return render_template('search.html', app_version=CURRENT_APP_VERSION)

# New route for the about page
@app.route('/about')
def about_page():
    """Renders the about HTML page."""
    return render_template('about.html', app_version=CURRENT_APP_VERSION)

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

@app.route('/search_cached', methods=['GET'])
def search_cached():
    """
    Searches through cached analysis results by URL or title.
    """
    query = request.args.get('query', '').lower()
    results = []

    for entry_name in os.listdir(CACHE_DIR):
        entry_path = os.path.join(CACHE_DIR, entry_name)
        analysis_file = os.path.join(entry_path, 'analysis.json')

        if os.path.isdir(entry_path) and os.path.exists(analysis_file):
            try:
                with open(analysis_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    url = data.get('url', '').lower()
                    title = data.get('title', '').lower()

                    if query in url or query in title:
                        results.append({
                            "url": data.get('url'),
                            "title": data.get('title', 'Untitled Document'),
                            "timestamp": data.get('timestamp')
                        })
            except json.JSONDecodeError:
                print(f"Warning: Corrupted JSON cache file found during search: {analysis_file}")
            except Exception as e:
                print(f"Error reading cache entry during search {analysis_file}: {e}")

    # Sort results by most recent first
    results.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
    return jsonify(results)


if __name__ == '__main__':
    # For local development, you can run: python app.py
    # In a production Gunicorn/WSGI environment, the server will handle this.
    app.run(debug=True, host='127.0.0.1', port=5000)
