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
import shutil
from packaging.version import parse as parse_version
import urllib.parse
import ipaddress
import socket
import re # Import for regular expressions
# Removed csv import, will use json instead

# Playwright imports
#from playwright.sync_api import sync_playwright # For synchronous Playwright usage in a thread

# Load environment variables from .env file (for API key during local development)
load_dotenv()

app = Flask(__name__)

# Configuration
CACHE_DIR = './cache/TOSCheck'
os.makedirs(CACHE_DIR, exist_ok=True) # Ensure cache directory exists

# Define the path for the contracts log file, now JSON
CONTRACTS_FILE = os.path.join(CACHE_DIR, 'contracts.json')

# --- Versioning Configuration ---
VERSION_FILE = 'version.txt'

CURRENT_APP_VERSION = "1.0.1.18" # Incremented version number for changing API

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
            "text": """Analyze the following legal document (e.g., Privacy Policy, Terms of Service) and extract the following information. For each attribute, provide the requested details and a direct, verbatim quote (citation) from the document that supports your finding. The citation MUST be a direct quote from the provided "Document Text" and should be as concise as possible while still accurately representing the point. If combining distinct portions of text for a single citation, separate them using "..." or " ... ". If an attribute or sub-attribute is not explicitly mentioned or applicable, state 'N/A' for strings/arrays, 'false' for booleans, or "Not explicitly stated" for dates. Use **bold** for key terms and *italics* for emphasis where appropriate in descriptions. Use markdown lists for multiple points.

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
    * List potential risks, unfavorable clauses, or significant concerns for the user, based on the document. For each concern, provide a very concise, bullet-point style summary (1-2 sentences maximum) and a direct citation from the document. If no specific concerns are found, state 'N/A' for point and citation.
    * Format: Array of objects, each with `point` (string) and `citation` (string).

7.  **Notification & Liability Before Service Action (`notification_liability_before_action`)**:
    * `commitment_exists`: Boolean (true/false) - Is there a commitment to notify the user or limit liability before significant service actions (e.g., suspension, major changes)?
    * `details`: Explanation of the commitment.
    * `citation`: Direct, verbatim quote from the document.

8.  **Prohibited Actions (User Conduct) (`prohibited_actions`)**:
    * List activities forbidden for users.
    * Format: Array of objects, each with `action` (string), `citation` (string).

9.  **Reasons for Service Termination/Suspension (`termination_reasons`)**:
    * List conditions under which the service can terminate/suspend a user's account.
    * Format: Array of objects, each with `reason` (string), `citation` (string).

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
    * `citation`: Direct, verbatim quote from the document.

13. **Limitation of Liability (`limitation_of_liability`)**:
    * `exists`: Boolean (true/false) - Is there a clause limiting service provider's liability?
    * `summary`: Concise summary of the limitation.
    * `citation`: Direct, verbatim quote from the document.

14. **Intellectual Property Rights (`intellectual_property`)**:
    * `ownership_of_service`: Who owns the service's IP.
    * `user_content_rights`: How user-generated content IP is handled (e.g., user retains ownership, grants license).
    * `citation`: Direct, verbatim quote from the document covering both aspects.

15. **Changes to Terms (`changes_to_terms`)**:
    * `method`: How terms can be modified (e.g., "Unilateral changes with notice").
    * `notification_period`: How many days notice, if any.
    * `user_consent_required`: Boolean (true/false) - Is user consent required for changes?
    * `citation`: Direct, verbatim quote from the document.

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

def _extract_company_name_from_url(url):
    """
    Extracts and cleans a potential company name from a URL's hostname.
    e.g., "https://www.openai.com/policies/row-terms-of-use/" -> "OpenAI"
    "https://help.instagram.com/581066165581870" -> "Instagram"
    "https://www.google.com" -> "Google"
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname

        if not hostname:
            return None

        # Remove 'www.' prefix and split by dot
        domain_parts = hostname.replace('www.', '').split('.')

        # Prioritize common TLDs and take the part before it
        # e.g., 'example.com' -> 'example', 'example.co.uk' -> 'example'
        if len(domain_parts) >= 2:
            # Check for common multi-part TLDs like co.uk, com.au, etc.
            if len(domain_parts) >= 3 and (domain_parts[-2] + '.' + domain_parts[-1]) in ['co.uk', 'com.au', 'org.uk', 'net.au']:
                company_name = domain_parts[-3]
            else:
                company_name = domain_parts[-2] # Take the part before the last TLD (e.g., 'openai' from 'openai.com')
            
            # Clean and capitalize
            # Remove any trailing numbers or non-alphabetic characters
            company_name = re.sub(r'[^a-zA-Z]+$', '', company_name)
            
            # Handle specific patterns like "ai" and capitalize
            if company_name.lower().endswith('ai'):
                company_name = company_name[:-2].capitalize() + ' AI'
            else:
                company_name = company_name.capitalize()
            
            return company_name
        return None
    except Exception as e:
        print(f"Error extracting company name from URL {url}: {e}")
        return None

def _get_title_from_html(soup, url):
    """
    Extracts the most relevant title from a BeautifulSoup object.
    Prioritizes <title>, then <h1>, then tries to infer from URL.
    Also tries to prepend company name if title is generic.
    """
    page_title = None
    
    # 1. Try <title> tag
    if soup.title and soup.title.string:
        page_title = soup.title.string.strip()

    # 2. Fallback to <h1> tag
    if not page_title and soup.find('h1') and soup.find('h1').string:
        page_title = soup.find('h1').string.strip()

    # 3. Get company name from URL
    company_name = _extract_company_name_from_url(url)
    
    if page_title:
        # Normalize title for comparison (lowercase, remove common legal terms)
        normalized_page_title = page_title.lower()
        common_legal_terms = ['terms of service', 'privacy policy', 'terms of use', 'legal', 'policy', 'conditions']
        
        # Check if the title is generic or very short
        is_generic = any(term in normalized_page_title for term in common_legal_terms) or \
                     len(page_title.split()) <= 3 # Consider short titles generic

        if is_generic and company_name and company_name.lower() not in normalized_page_title:
            # Prepend company name if title is generic and company name is not already present
            # Ensure no duplicate legal terms if prepending
            for term in common_legal_terms:
                if normalized_page_title.startswith(term):
                    return f"{company_name} {page_title}"
            return f"{page_title} | {company_name}"
        return page_title
    
    # 4. If no title found, use company name from URL or default
    if company_name:
        return f"{company_name} Document" # e.g., "Perplexity AI Document"
    
    return "Untitled Document"

'''
def _get_document_text_playwright(url):
    """
    Fetches HTML content using Playwright for pages that require JavaScript rendering.
    Returns a tuple: (text_content, page_title, raw_html_content)
    """
    print(f"Attempting to scrape with Playwright: {url}")
    raw_html_content = ""
    text_content = ""
    page_title = "Untitled Document (Playwright)" # Default before scraping

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True # Run in headless mode
            page = browser.new_page()
            page.set_default_timeout(60000) # 60 seconds timeout for page operations

            # Navigate to the URL
            page.goto(url)

            # Wait for the network to be idle, indicating most content has loaded
            page.wait_for_load_state('networkidle')

            # Get the full HTML content of the page
            raw_html_content = page.content()

            # Use BeautifulSoup to parse the HTML and extract text
            soup = BeautifulSoup(raw_html_content, 'html.parser')

            # Extract title using the new helper function
            page_title = _get_title_from_html(soup, url)

            # Attempt to extract main content.
            main_content = soup.find('body') or soup.find('article') or soup.find('main')

            if not main_content:
                text_content = "Could not extract main content from the page using Playwright."
            else:
                paragraphs = main_content.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li'])
                text_content = "\n".join([elem.get_text(separator=" ", strip=True) for elem in paragraphs])
                text_content = ' '.join(text_content.split()) # Basic sanitization

            browser.close()
            return text_content, page_title, raw_html_content

    except Exception as e:
        print(f"Error fetching URL with Playwright {url}: {e}")
        return f"Error fetching URL with Playwright: {e}", page_title, raw_html_content
'''

def get_document_text(url):
    """
    Fetches HTML content from a given URL and extracts the main text content.
    Includes more comprehensive headers to mimic a browser.
    Ensures UTF-8 decoding.
    Attempts to use requests first, then falls back to Playwright if requests fails
    to get meaningful content.
    Returns a tuple: (text_content, page_title, raw_html_content)
    """
    if not is_safe_url(url):
        print(f"SSRF Prevention: Attempted to scrape unsafe URL: {url}")
        return "", "Unsafe URL", "" # Return empty strings for content and html, and a specific title

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'DNT': '1', # Do Not Track request header
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    
    # --- Attempt with requests first ---
    requests_text_content = ""
    requests_page_title = "Untitled Document (Requests)" # Default before scraping
    requests_raw_html_content = ""
    requests_success = False

    try:
        print(f"Attempting to scrape with requests: {url}")
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        response.encoding = 'utf-8' # Force UTF-8 decoding

        requests_raw_html_content = response.text
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract title using the new helper function
        requests_page_title = _get_title_from_html(soup, url)

        main_content = soup.find('body') or soup.find('article') or soup.find('main')

        if main_content:
            paragraphs = main_content.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li'])
            requests_text_content = "\n".join([elem.get_text(separator=" ", strip=True) for elem in paragraphs])
            requests_text_content = ' '.join(requests_text_content.split())

            # Check if extracted text is substantial enough
            if len(requests_text_content) > 100: # Arbitrary threshold for "meaningful content"
                requests_success = True
        else:
            print(f"Requests: Could not find main content for {url}. Falling back to Playwright.")

    except requests.exceptions.RequestException as e:
        print(f"Requests error fetching {url}: {e}. Falling back to Playwright.")
    except Exception as e:
        print(f"Requests error processing content for {url}: {e}. Falling back to Playwright.")

    # --- Fallback to Playwright if requests failed or got insufficient content ---
    if not requests_success:
        print(f"Requests failed to get meaningful content for {url}.")
        #return _get_document_text_playwright(url)
        return "", "", "" #playwright isnt working yet
    else:
        print(f"Requests successfully scraped {url}.")
        return requests_text_content, requests_page_title, requests_raw_html_content

def _log_contract_details(url, page_title, used_raw_html):
    """
    Logs details of the analyzed contract to a JSON file.
    If an entry with the same URL already exists, it updates that entry.
    Otherwise, it appends a new entry.
    """
    company_name = _extract_company_name_from_url(url)
    if not company_name:
        company_name = "N/A" # Fallback if company name can't be extracted

    # Determine the effective title for the log, preferring the extracted title
    effective_title = page_title if page_title and page_title != "Untitled Document" else "N/A"

    new_entry = {
        "company_name": company_name,
        "company_url": url,
        "document_title": effective_title,
        "manual_html_provided": used_raw_html,
        "timestamp": time.time() # Add timestamp for easier sorting/tracking
    }

    all_entries = []
    
    # Read existing data
    if os.path.exists(CONTRACTS_FILE):
        try:
            with open(CONTRACTS_FILE, 'r', encoding='utf-8') as f:
                all_entries = json.load(f)
                if not isinstance(all_entries, list): # Ensure it's a list
                    all_entries = []
        except (json.JSONDecodeError, Exception) as e:
            print(f"Error reading existing contracts.json: {e}. Starting with empty data.")
            all_entries = []

    # Check if URL exists and update, otherwise append
    url_found = False
    for i, entry in enumerate(all_entries):
        if entry.get("company_url") == url:
            all_entries[i] = new_entry # Overwrite existing entry
            url_found = True
            break
    
    if not url_found:
        all_entries.append(new_entry)

    # Write all data back to the file
    try:
        with open(CONTRACTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(all_entries, f, ensure_ascii=False, indent=4)
    except Exception as e:
        print(f"Error writing contract details to JSON: {e}")


def analyze_document_task(url_hash, url, raw_html_input=None, used_raw_html_for_analysis=False): # Add raw_html_input parameter
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

    try:
        if raw_html_input and raw_html_input.strip():
            print(f"Using provided raw HTML for analysis of {url}.")
            raw_html_content = raw_html_input
            soup = BeautifulSoup(raw_html_content, 'html.parser')

            # Extract title from provided HTML using the new helper function
            page_title = _get_title_from_html(soup, url)

            # Extract text content from provided HTML
            main_content = soup.find('body') or soup.find('article') or soup.find('main')
            if not main_content:
                document_text = "Could not extract main content from the provided HTML."
                final_error_message = document_text
            else:
                paragraphs = main_content.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li'])
                document_text = "\n".join([elem.get_text(separator=" ", strip=True) for elem in paragraphs])
                document_text = ' '.join(document_text.split())

                # Limit document text to prevent excessively large prompts
                MAX_TEXT_LENGTH = 500000
                if len(document_text) > MAX_TEXT_LENGTH:
                    document_text = document_text[:MAX_TEXT_LENGTH] + "\n... (document truncated)"

            # Always write the provided raw HTML to cache
            with open(html_file_path, 'w', encoding='utf-8') as f:
                f.write(raw_html_content)

        else: # Normal scraping if no raw_html_input is provided
            print(f"Scraping URL: {url}")
            # 1. Web Scraping and Text Extraction (now includes Playwright fallback)
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
                MAX_TEXT_LENGTH = 500000  # Characters (10x original, not 1000x)
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
        # For provided HTML, we assume it's "successful enough" if it's not empty after parsing.
        html_file_size_ok = os.path.exists(html_file_path) and os.path.getsize(html_file_path) >= 1024
        raw_text_file_size_ok = os.path.exists(raw_text_file_path) and os.path.getsize(raw_text_file_path) >= 1024

        # Determine if we should proceed with LLM analysis
        # If raw_html_input was used, we only need document_text to be non-empty.
        if used_raw_html_for_analysis: # Use the passed flag
            proceed_with_llm = bool(document_text and not final_error_message)
        else:
            proceed_with_llm = html_file_size_ok and raw_text_file_size_ok and document_text and not ("Error fetching URL" in document_text or "Could not extract main content" in document_text or "Unsafe URL" in document_text)

        if not proceed_with_llm:
            error_details = []
            if not html_file_size_ok and not used_raw_html_for_analysis: # Only check file size if not using provided HTML
                error_details.append(f"html.txt ({os.path.getsize(html_file_path) if os.path.exists(html_file_path) else 0} bytes) is too small")
            if not raw_text_file_size_ok and not used_raw_html_for_analysis: # Only check file size if not using provided HTML
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
            "title": page_title, # Use the potentially enhanced page_title
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
        
        # Log contract details to JSON (updated function)
        _log_contract_details(url, page_title, used_raw_html_for_analysis)


@app.route('/version', methods=['GET'])
def get_version():
    """Returns the current version of the app."""
    return jsonify({"version": CURRENT_APP_VERSION})

@app.route('/')
def index():
    """Renders the main frontend HTML page or returns JSON analysis if format=json and url are provided."""
    # --- Begin support for GET /?format=json&url=... ---
    req_format = request.args.get('format', '').lower()
    url = request.args.get('url', '')
    if req_format == 'json' and url:
        # Validate URL
        if not url.startswith('http://') and not url.startswith('https://'):
            return jsonify({"error": "Invalid URL format. Must start with http:// or https://."}), 400

        url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()
        cache_dir_path = os.path.join(CACHE_DIR, url_hash)
        cache_file_path = os.path.join(cache_dir_path, 'analysis.json')

        # Check cache
        if os.path.exists(cache_file_path):
            try:
                with open(cache_file_path, 'r', encoding='utf-8') as f:
                    cached_analysis = json.load(f)
                return jsonify(cached_analysis)
            except Exception as e:
                return jsonify({"error": f"Error reading cached analysis: {e}"}), 500

        # If not cached, start analysis (asynchronously)
        if url_hash not in job_statuses:
            job_statuses[url_hash] = {"status": "started", "progress": 0}
            executor.submit(analyze_document_task, url_hash, url, None, False)

        # Return processing status
        return jsonify({"job_id": url_hash, "status": "processing"})

    # --- End support for GET /?format=json&url=... ---
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

# New route for the changelog page
@app.route('/changelog')
def changelog_page():
    """Renders the changelog HTML page."""
    return render_template('changelog.html', app_version=CURRENT_APP_VERSION)

@app.route('/analyze', methods=['POST'])
def analyze_url():
    """
    Endpoint to initiate document analysis.
    Checks cache first, then starts an asynchronous task if not cached.
    Supports ?format=json to return full JSON result if available.
    """
    data = request.get_json()
    url = data.get('url')
    raw_html_input = data.get('raw_html_input') # New parameter

    if not url:
        return jsonify({"error": "URL is required."}), 400

    # Basic URL validation
    if not url.startswith('http://') and not url.startswith('https://'):
        return jsonify({"error": "Invalid URL format. Must start with http:// or https://."}), 400

    # Flag to indicate if raw HTML was used for this analysis
    used_raw_html_for_analysis = bool(raw_html_input and raw_html_input.strip())

    # --- SSRF Prevention: Validate URL safety before proceeding ---
    if not used_raw_html_for_analysis:
        if not is_safe_url(url):
            return jsonify({"error": "Provided URL is not allowed. Potential security risk."}), 403
    # --- END SSRF Prevention ---

    url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()
    cache_dir_path = os.path.join(CACHE_DIR, url_hash)
    cache_file_path = os.path.join(cache_dir_path, 'analysis.json')

    force_re_analysis_with_html = used_raw_html_for_analysis
    cached_analysis = None
    if os.path.exists(cache_file_path) and not force_re_analysis_with_html:
        try:
            with open(cache_file_path, 'r', encoding='utf-8') as f:
                cached_analysis = json.load(f)

            cached_version_str = cached_analysis.get('version', '0.0.0')
            if parse_version(cached_version_str) < parse_version(CURRENT_APP_VERSION):
                print(f"Cached version {cached_version_str} is older than current version {CURRENT_APP_VERSION} for {url}. Deleting cache and re-analyzing.")
                shutil.rmtree(cache_dir_path)
                cached_analysis = None
            else:
                print(f"Serving cached analysis (version {cached_version_str}) for {url}")
                job_statuses[url_hash] = {"status": "completed", "result": cached_analysis, "progress": 100}
                # --- Begin format=json support ---
                if request.args.get('format', '').lower() == 'json':
                    return jsonify(cached_analysis)
                # --- End format=json support ---
                return jsonify({"job_id": url_hash, "status": "completed", "result": cached_analysis})

        except json.JSONDecodeError as e:
            print(f"Error reading cached JSON for {url_hash}: {e}. Cache might be corrupted. Re-analyzing.")
            if os.path.exists(cache_dir_path):
                shutil.rmtree(cache_dir_path)
            cached_analysis = None
        except Exception as e:
            print(f"An unexpected error occurred during cache check for {url_hash}: {e}. Re-analyzing.")
            if os.path.exists(cache_dir_path):
                shutil.rmtree(cache_dir_path)
            cached_analysis = None

    print(f"Starting new analysis for {url} (Job ID: {url_hash})")
    job_statuses[url_hash] = {"status": "started", "progress": 0}
    executor.submit(analyze_document_task, url_hash, url, raw_html_input, used_raw_html_for_analysis)

    # --- Begin format=json support for processing state ---
    if request.args.get('format', '').lower() == 'json':
        return jsonify({"job_id": url_hash, "status": "processing"})
    # --- End format=json support ---

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
    Filters out documents that could not be scraped.
    Returns up to 5 most recent analyses with their URL and title.
    """
    recent_items = []
    
    if os.path.exists(CONTRACTS_FILE):
        try:
            with open(CONTRACTS_FILE, 'r', encoding='utf-8') as f:
                contracts_data = json.load(f)
                if not isinstance(contracts_data, list):
                    contracts_data = []
        except (json.JSONDecodeError, Exception) as e:
            print(f"Error reading contracts.json for recent analyses: {e}. Returning empty list.")
            contracts_data = []
    else:
        contracts_data = []

    # Filter out entries that represent failed scrapes or generic titles
    # A more robust check might involve checking the corresponding analysis.json for 'error_message_overall'
    # For now, we'll use the title as a heuristic.
    filtered_contracts = [
        entry for entry in contracts_data
        if entry.get('document_title') != 'N/A' and 
           entry.get('document_title') != 'Untitled Document' and
           not (entry.get('manual_html_provided') and "failed to extract" in entry.get('document_title', '').lower()) # Exclude manual HTML entries that were just error messages
    ]

    # Sort by timestamp, most recent first
    filtered_contracts.sort(key=lambda x: x.get('timestamp', 0), reverse=True)

    # Get top 5 (or fewer if less than 5)
    recent_items = []
    for entry in filtered_contracts[:5]:
        recent_items.append({
            "url": entry.get('company_url', ''),
            "title": entry.get('document_title', 'Untitled Document'),
            "timestamp": entry.get('timestamp', 0)
        })

    return jsonify(recent_items)

@app.route('/search_cached', methods=['GET'])
def search_cached():
    """
    Searches through cached analysis results by URL or title.
    Filters out documents that could not be scraped.
    """
    query = request.args.get('query', '').lower()
    results = []

    if os.path.exists(CONTRACTS_FILE):
        try:
            with open(CONTRACTS_FILE, 'r', encoding='utf-8') as f:
                contracts_data = json.load(f)
                if not isinstance(contracts_data, list):
                    contracts_data = []
        except (json.JSONDecodeError, Exception) as e:
            print(f"Error reading contracts.json for search: {e}. Returning empty list.")
            contracts_data = []
    else:
        contracts_data = []

    for entry in contracts_data:
        url = entry.get('company_url', '').lower()
        title = entry.get('document_title', '').lower()
        company_name = entry.get('company_name', '').lower()

        # Filter out entries that represent failed scrapes or generic titles
        if entry.get('document_title') == 'N/A' or \
           entry.get('document_title') == 'Untitled Document' or \
           (entry.get('manual_html_provided') and "failed to extract" in entry.get('document_title', '').lower()):
            continue # Skip this entry if it's an unscraped document

        if query in url or query in title or query in company_name:
            results.append({
                "url": entry.get('company_url', ''),
                "title": entry.get('document_title', 'Untitled Document'),
                "timestamp": entry.get('timestamp', 0)
            })

    # Sort results by most recent first
    results.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
    return jsonify(results)


if __name__ == '__main__':
    # For local development, you can run: python app.py
    # In a production Gunicorn/WSGI environment, the server will handle this.
    app.run(debug=True, host='127.0.0.1', port=5000)
