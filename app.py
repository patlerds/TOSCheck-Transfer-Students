# app.py
import os
import hashlib
import json
import requests
import time
from flask import Flask, request, jsonify, render_template
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import concurrent.futures
import shutil
from packaging.version import parse as parse_version
import urllib.parse
import ipaddress
import socket
import re
import io
import pdfplumber
from flask_cors import CORS

# Load environment variables from .env file (for API key during local development)
load_dotenv()

app = Flask(__name__)
# Initialize CORS for Flask app
CORS(app, resources={r"/*": {"origins": [
    "https://tos.nishanth.us", # Allow own domain
    "chrome-extension://npccnppomjfdohmalokopnkjooindffn" # Allow  Chrome Extension
]}})


# Configuration
CACHE_DIR = './cache/TOSCheck'
os.makedirs(CACHE_DIR, exist_ok=True)

CONTRACTS_FILE = os.path.join(CACHE_DIR, 'contracts.json')

# --- Versioning Configuration ---
VERSION_FILE = 'version.txt'
CURRENT_APP_VERSION = "2.3.1"
# --- End Versioning Configuration ---

def _version_lt(v1: str, v2: str) -> bool:
    """Safe version comparison. Any version containing 'x' is treated as current — never older."""
    if 'x' in v2:
        return False
    try:
        return parse_version(v1) < parse_version(v2)
    except Exception:
        return False

# Gemini API Key - Prioritize environment variables.
GEMINI_API_KEY_EXPLICIT = os.getenv("GEMINI_API_KEY")
# Models tried in order; falls back to the next one on 429 (rate limit) or 404 (model unavailable).
# Only models with confirmed quota on this API key should be listed here.
# To find the exact model ID: Google AI Studio → left sidebar → hover model name → copy API name.
GEMINI_MODELS = [
    "gemini-3-flash-preview",  # primary
    "gemini-2.5-flash",        # fallback (confirmed working)
]
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

# In-memory dictionary to track job statuses for asynchronous tasks
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
            # getaddrinfo returns (family, socktype, proto, canonname, sockaddr);
            # sockaddr[0] is the IP string for both IPv4 and IPv6.
            ip_addresses = [info[4][0] for info in socket.getaddrinfo(hostname, None)]
        except socket.gaierror:
            print(f"Warning: Could not resolve hostname for {hostname}")
            return False

        for ip_str in ip_addresses:
            try:
                ip_addr = ipaddress.ip_address(ip_str)
                for forbidden_range in FORBIDDEN_IP_RANGES:
                    if ip_addr in forbidden_range:
                        print(f"SSRF Alert: Blocked access to private IP range {ip_str} for URL {url}")
                        return False
                if ip_str == "169.254.169.254":
                    print(f"SSRF Alert: Blocked access to metadata service IP {ip_str} for URL {url}")
                    return False
            except ValueError:
                continue

        return True

    except Exception as e:
        print(f"Error during URL safety check for {url}: {e}")
        return False

# --- End SSRF Prevention Configuration ---

def get_gemini_api_key():
    """
    Returns the Gemini API key. Resolution order:
    1. __api_key__ env var (injected by Canvas/hosted environments)
    2. GEMINI_API_KEY env var / .env file (local development)
    3. gemini.txt file in known server locations (production fallback)
    """
    canvas_key = os.environ.get("__api_key__")
    if canvas_key:
        return canvas_key

    if GEMINI_API_KEY_EXPLICIT:
        return GEMINI_API_KEY_EXPLICIT

    # Last-resort: look for a plaintext key file in known server locations
    key_locations = [
        os.path.join(os.path.dirname(__file__), '..', 'gemini.txt'),
        '/home/nish/web/gemini.txt',
    ]
    for file_path in key_locations:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                key = f.read().strip()
            if key:
                return key

    print("Warning: Gemini API Key not found. Set GEMINI_API_KEY in .env or environment.")
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
    * Extract the 5-7 most important key points from the document, relevant to a general user and explained in a user-friendly manner. Each point must include a direct citation from the document.
    * Format: Array of objects, each with `point` (string) and `citation` (string).

6.  **Things User Should Be Worried About (`user_concerns`)**:
    * List ALL potential risks, unfavorable clauses, or significant concerns for the user, based on the document, explained in a user-friendly manner. For each concern, provide a very concise, bullet-point style summary (1-2 sentences maximum) and a direct citation from the document. If no specific concerns are found, state 'N/A' for point and citation.
    * Format: Array of objects, each with `point` (string), `citation` (string).

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

16.  **Common TOS Concerns (`common_tos_concerns`)**:
    * For each of the following, state if the issue is present, summarize the relevant clause, and provide a direct citation:
        - Limitation of Liability
        - Arbitration & Dispute Resolution
        - Changes to Terms
        - Data Collection & Privacy
        - Termination of Service
        - User Content & Intellectual Property
        - Prohibited Conduct
        - Jurisdiction & Governing Law
        - No Warranty/“As Is” Disclaimer
        - Indemnification
    * Format: Array of objects, each with `concern_type` (string), `present` (boolean), `summary` (string), and `citation` (string).

Document Text:
""",
            "schema": {
                "type": "OBJECT",
                "properties": {
                    "product_coverage": {"type": "ARRAY", "items": {"type": "STRING"}},
                    "last_update_date": {"type": "STRING"},
                    "ten_word_summary": {"type": "STRING"},
                    "one_paragraph_summary": {"type": "STRING"},
                    "key_points": {
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
                    "user_concerns": {
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
                            "notification_period": {"type": "STRING"},
                            "user_consent_required": {"type": "BOOLEAN"},
                            "citation": {"type": "STRING"}
                        },
                        "required": ["method", "notification_period", "user_consent_required", "citation"]
                    },
                    "common_tos_concerns": {
                        "type": "ARRAY",
                        "items": {
                            "type": "OBJECT",
                            "properties": {
                                "concern_type": {"type": "STRING"},
                                "present": {"type": "BOOLEAN"},
                                "summary": {"type": "STRING"},
                                "citation": {"type": "STRING"}
                            },
                            "required": ["concern_type", "present", "summary", "citation"]
                        }
                    },
                },
                "required": [
                    "product_coverage", "last_update_date", "ten_word_summary", "one_paragraph_summary",
                    "key_points", "user_concerns",
                    "notification_liability_before_action",
                    "prohibited_actions", "termination_reasons", "data_protections",
                    "privacy_protections_user_rights", "dispute_resolution", "limitation_of_liability",
                    "intellectual_property", "changes_to_terms", "common_tos_concerns"
                ]
            }
        }
    }

    prompts["eligibility_check"] = {
        "text": """You are analyzing a university organization bylaw, club constitution, student handbook, or similar policy document.

Your task is to find TWO specific types of potentially discriminatory eligibility rules:

1. **Tenure/time requirements for leadership**: Any rule that requires a member to have been in the organization, club, or university for a minimum amount of time (semesters, years, meetings attended, etc.) before they can run for or hold a leadership or officer position.

2. **Transfer student restrictions**: Any rule that disadvantages, excludes, or creates additional hurdles for transfer students — students who enrolled at the university in their junior year or later (i.e., with 60+ credit hours transferred in). Look for rules based on: semesters enrolled at this university, credit hours earned at this institution, class standing at time of joining, number of semesters remaining, or any language that effectively bars or disadvantages late-enrolling students.

For each finding:
- Quote the exact rule verbatim
- Explain clearly why it is a tenure requirement or transfer student barrier
- Rate the severity: "Mild" (minor hurdle), "Moderate" (significant barrier), or "Severe" (effectively excludes the group)

If no such rules are found for a category, say so explicitly.

Document Text:
""",
        "schema": {
            "type": "OBJECT",
            "properties": {
                "tenure_requirements": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "rule": {"type": "STRING"},
                            "explanation": {"type": "STRING"},
                            "citation": {"type": "STRING"},
                            "severity": {"type": "STRING"}
                        },
                        "required": ["rule", "explanation", "citation", "severity"]
                    }
                },
                "transfer_student_barriers": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "rule": {"type": "STRING"},
                            "explanation": {"type": "STRING"},
                            "citation": {"type": "STRING"},
                            "severity": {"type": "STRING"}
                        },
                        "required": ["rule", "explanation", "citation", "severity"]
                    }
                },
                "overall_summary": {"type": "STRING"}
            },
            "required": ["tenure_requirements", "transfer_student_barriers", "overall_summary"]
        }
    }

    if prompt_type not in prompts:
        return {"error": f"Invalid prompt type: {prompt_type}"}

    prompt_config = prompts[prompt_type]
    full_prompt = prompt_config["text"] + document_text

    payload = {
        "contents": [{"role": "user", "parts": [{"text": full_prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": prompt_config["schema"]
        }
    }

    last_error = "All Gemini models exhausted."
    for model in GEMINI_MODELS:
        url = GEMINI_BASE_URL.format(model=model) + f"?key={api_key}"
        try:
            response = requests.post(
                url,
                headers={'Content-Type': 'application/json'},
                json=payload,
                timeout=300
            )

            if response.status_code in (429, 404):
                reason = "rate-limited" if response.status_code == 429 else "not found"
                print(f"Gemini [{model}] {reason} ({response.status_code}), trying next...")
                last_error = f"Model {model} unavailable ({response.status_code})."
                continue  # try next model

            response.raise_for_status()
            result = response.json()

            if result and result.get("candidates") and result["candidates"][0].get("content") and result["candidates"][0]["content"].get("parts"):
                print(f"Gemini [{model}] succeeded.")
                if model != GEMINI_MODELS[0]:
                    print(f"  ^ used fallback (primary was rate-limited or unavailable)")
                json_string = result["candidates"][0]["content"]["parts"][0]["text"]
                return json.loads(json_string)
            else:
                return {"error": "Unexpected Gemini API response structure."}

        except requests.exceptions.RequestException as e:
            print(f"Gemini API request failed for model {model}: {e}")
            last_error = f"Gemini API request failed: {e}"
            # Don't fall through to next model on non-429 errors (network issue, auth, etc.)
            return {"error": last_error}
        except json.JSONDecodeError as e:
            print(f"Failed to decode Gemini API response JSON from {model}: {e}")
            return {"error": "Failed to parse Gemini API response."}
        except Exception as e:
            print(f"Unexpected error during Gemini API call to {model}: {e}")
            return {"error": f"An unexpected error occurred: {e}"}

    return {"error": last_error}

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
        # Playwright fallback is not yet implemented.
        return "", "", ""
    else:
        print(f"Requests successfully scraped {url}.")
        return requests_text_content, requests_page_title, requests_raw_html_content

def _log_contract_details(url, page_title, manual_html_content=""):
    """
    Logs details of the analyzed contract to a JSON file.
    If an entry with the same URL already exists, it updates that entry.
    Otherwise, it appends a new entry.
    manual_html_content will be stored if provided, otherwise an empty string.
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
        "manual_html_provided": manual_html_content if manual_html_content and manual_html_content.strip() else "",
        "timestamp": time.time()
    }

    all_entries = []

    # Read existing data
    if os.path.exists(CONTRACTS_FILE):
        try:
            with open(CONTRACTS_FILE, 'r', encoding='utf-8') as f:
                all_entries = json.load(f)
                if not isinstance(all_entries, list):
                    all_entries = []
        except (json.JSONDecodeError, Exception) as e:
            print(f"Error reading existing contracts.json: {e}. Starting with empty data.")
            all_entries = []

    url_found = False
    for i, entry in enumerate(all_entries):
        if entry.get("company_url") == url:
            all_entries[i] = new_entry
            url_found = True
            break

    if not url_found:
        all_entries.append(new_entry)

    try:
        with open(CONTRACTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(all_entries, f, ensure_ascii=False, indent=4)
    except Exception as e:
        print(f"Error writing contract details to JSON: {e}")


def find_cached_pdf_by_filename(safe_filename, exclude_hash):
    """Returns (job_id, title) if a cached PDF with this filename exists under a different hash, else None."""
    target_url = f"urn:pdf-upload:{safe_filename}"
    for entry in os.scandir(CACHE_DIR):
        if not entry.is_dir() or entry.name == exclude_hash:
            continue
        analysis_path = os.path.join(entry.path, 'analysis.json')
        if not os.path.exists(analysis_path):
            continue
        try:
            with open(analysis_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if data.get('url') == target_url and not data.get('error_message_overall'):
                return entry.name, data.get('title', safe_filename)
        except Exception:
            continue
    return None


def analyze_document_task(url_hash, url, raw_html_input=None, pdf_text=None, eligibility_only=False):
    """
    Background task that handles the full document analysis pipeline.
    Runs in a ThreadPoolExecutor thread — must not block the Flask main thread.

    Input priority: pdf_text > raw_html_input > URL scraping.
    Always writes analysis.json and updates job_statuses, even on failure,
    so callers can inspect what went wrong.
    """
    document_text = ""
    page_title = "Untitled Document"
    raw_html_content = ""
    full_analysis_res = {"error": "Analysis not yet performed or failed early."}
    overall_status = "failed"   # pessimistic default; set to "completed" on success
    final_error_message = None
    document_raw_text_content = ""
    is_irrelevant = False

    used_raw_html_for_analysis = bool(raw_html_input and raw_html_input.strip())

    cache_path = os.path.join(CACHE_DIR, url_hash)
    os.makedirs(cache_path, exist_ok=True)
    html_file_path = os.path.join(cache_path, 'html.txt')
    raw_text_file_path = os.path.join(cache_path, 'raw.txt')
    analysis_json_file_path = os.path.join(cache_path, 'analysis.json')

    job_statuses[url_hash] = {"status": "scraping", "progress": 10}

    try:
        # ── Stage 1: Content Acquisition ─────────────────────────────────────────
        # Priority: pdf_text (already extracted) > raw_html_input (user-pasted) > URL scrape.
        MAX_TEXT_LENGTH = 500000  # chars; keeps prompts within Gemini context limits

        if pdf_text:
            print(f"Using extracted PDF text for analysis ({url}).")
            document_text = pdf_text[:MAX_TEXT_LENGTH]
            if len(pdf_text) > MAX_TEXT_LENGTH:
                document_text += "\n... (document truncated)"
            raw_html_content = ""
            pdf_filename = url.split("urn:pdf-upload:")[-1] if "urn:pdf-upload:" in url else url
            page_title = "PDF: " + os.path.splitext(pdf_filename)[0]
            is_irrelevant = False   # user explicitly chose this file — skip title gate

            with open(html_file_path, 'w', encoding='utf-8') as f:
                f.write("")  # html.txt intentionally empty for PDF uploads

        elif used_raw_html_for_analysis:
            print(f"Using provided raw HTML for analysis of {url}.")
            raw_html_content = raw_html_input
            soup = BeautifulSoup(raw_html_content, 'html.parser')
            page_title = _get_title_from_html(soup, url)

            main_content = soup.find('body') or soup.find('article') or soup.find('main')
            if not main_content:
                document_text = "Could not extract main content from the provided HTML."
                final_error_message = document_text
            else:
                paragraphs = main_content.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li'])
                document_text = ' '.join(
                    "\n".join([elem.get_text(separator=" ", strip=True) for elem in paragraphs]).split()
                )
                if len(document_text) > MAX_TEXT_LENGTH:
                    document_text = document_text[:MAX_TEXT_LENGTH] + "\n... (document truncated)"

            with open(html_file_path, 'w', encoding='utf-8') as f:
                f.write(raw_html_content)

        else:
            # Normal URL scrape — Playwright fallback is stubbed out (not yet functional).
            print(f"Scraping URL: {url}")
            scraped_text, scraped_title, scraped_html = get_document_text(url)

            raw_html_content = scraped_html
            with open(html_file_path, 'w', encoding='utf-8') as f:
                f.write(raw_html_content)

            scrape_errors = ("Error fetching URL", "Could not extract main content", "Unsafe URL")
            if not scraped_text or any(e in scraped_text for e in scrape_errors):
                final_error_message = scraped_text or "Failed to extract main text content from the page."
                document_text = final_error_message
            else:
                document_text = scraped_text
                page_title = scraped_title
                if len(document_text) > MAX_TEXT_LENGTH:
                    document_text = document_text[:MAX_TEXT_LENGTH] + "\n... (document truncated)"

        # raw.txt stores the text that was (or would be) sent to the LLM.
        # Also used by /analyze/eligibility to avoid re-scraping.
        with open(raw_text_file_path, 'w', encoding='utf-8') as f:
            f.write(document_text)
        document_raw_text_content = document_text

        # ── Stage 2: Content Validation ──────────────────────────────────────────
        # Gate 1 — did we get enough raw content to be worth sending to the LLM?
        # PDFs skip the html.txt size check (html.txt is intentionally empty).
        html_file_size_ok = pdf_text or (os.path.exists(html_file_path) and os.path.getsize(html_file_path) >= 1024)
        raw_text_file_size_ok = os.path.exists(raw_text_file_path) and os.path.getsize(raw_text_file_path) >= 1024
        scrape_errors = ("Error fetching URL", "Could not extract main content", "Unsafe URL")
        proceed_with_llm_based_on_scrape = (
            html_file_size_ok and raw_text_file_size_ok
            and document_text
            and not any(e in document_text for e in scrape_errors)
        )

        # Gate 2 — is the title recognisably a legal/policy document?
        # PDFs skip this; the user explicitly chose the file so we trust their intent.
        relevant_title_keywords = [
            'terms of service', 'privacy policy', 'terms of use', 'legal', 'policy',
            'policies', 'conditions', 'license', 'agreement', 'contract', 'EULA', 'act',
        ]
        if not pdf_text:
            is_irrelevant = not (page_title and any(kw in page_title.lower() for kw in relevant_title_keywords))

        if not proceed_with_llm_based_on_scrape:
            error_details = []
            if not used_raw_html_for_analysis:
                html_sz = os.path.getsize(html_file_path) if os.path.exists(html_file_path) else 0
                raw_sz  = os.path.getsize(raw_text_file_path) if os.path.exists(raw_text_file_path) else 0
                if html_sz < 1024:
                    error_details.append(f"html.txt ({html_sz} bytes) is too small")
                if raw_sz < 1024:
                    error_details.append(f"raw.txt ({raw_sz} bytes) is too small")
            if not document_text:
                error_details.append("extracted document text is empty")
            if any(e in document_text for e in scrape_errors):
                error_details.append(f"scraping/extraction error: {document_text}")

            final_error_message = "Scraping or text extraction failed: " + "; ".join(error_details)
            print(f"Warning: {final_error_message} for URL: {url} (Hash: {url_hash})")
            full_analysis_res["error"] = final_error_message
            overall_status = "failed"

        elif is_irrelevant:
            final_error_message = "Document title does not appear to be a legal policy."
            print(f"Warning: {final_error_message} for URL: {url} (Hash: {url_hash})")
            full_analysis_res["error"] = final_error_message
            full_analysis_res["is_irrelevant"] = True
            overall_status = "failed"

        else:
            # ── Stage 3: LLM Analysis ─────────────────────────────────────────────
            job_statuses[url_hash] = {"status": "analyzing", "progress": 30}

            if eligibility_only:
                elg_result = call_gemini_api(document_text, "eligibility_check")
                if elg_result.get("error"):
                    final_error_message = elg_result["error"]
                    full_analysis_res["error"] = final_error_message
                    overall_status = "failed"
                else:
                    with open(os.path.join(cache_path, 'eligibility.json'), 'w', encoding='utf-8') as f:
                        json.dump(elg_result, f)
                    full_analysis_res = {"eligibility_only": True}
                    overall_status = "completed"
            else:
                gemini_result = call_gemini_api(document_text, "comprehensive_analysis")
                if "error" in gemini_result:
                    final_error_message = gemini_result["error"]
                    full_analysis_res["error"] = final_error_message
                    overall_status = "failed"
                else:
                    full_analysis_res = gemini_result
                    overall_status = "completed"


    except Exception as e:
        final_error_message = f"An unexpected error occurred during analysis: {str(e)}"
        print(f"Error in analyze_document_task for {url}: {final_error_message}")
        full_analysis_res["error"] = final_error_message # Ensure error is in the JSON payload
        overall_status = "failed" # Ensure status is failed on unexpected exceptions


    finally:
        try:
            combined_analysis = {
                "version": CURRENT_APP_VERSION,
                "url": url,
                "title": page_title,
                "full_analysis": full_analysis_res,
                "document_raw_text": document_raw_text_content,
                "timestamp": time.time(),
                "is_irrelevant": is_irrelevant
            }

            if final_error_message:
                combined_analysis["error_message_overall"] = final_error_message

            try:
                with open(analysis_json_file_path, 'w', encoding='utf-8') as f:
                    json.dump(combined_analysis, f, ensure_ascii=False, indent=4)
            except Exception as write_err:
                print(f"Error writing analysis.json for {url_hash}: {write_err}")
                overall_status = "failed"
                final_error_message = f"Critical: Failed to save analysis JSON: {str(write_err)}"
                combined_analysis["error_message_overall"] = final_error_message

            current_progress = job_statuses.get(url_hash, {}).get("progress", 0)
            job_statuses[url_hash] = {
                "status": overall_status,
                "result": combined_analysis,
                "progress": 100 if overall_status == "completed" else current_progress
            }
            if overall_status == "failed" and final_error_message:
                job_statuses[url_hash]["error"] = final_error_message

            _log_contract_details(url, page_title, raw_html_input)

        except Exception as finally_err:
            # Last resort: ensure the job is never left in a perpetually pending state
            print(f"Critical error in finally block for {url_hash}: {finally_err}")
            job_statuses[url_hash] = {"status": "failed", "progress": 0, "error": str(finally_err)}


@app.route('/version', methods=['GET'])
def get_version():
    """Returns the current version of the app."""
    return jsonify({"version": CURRENT_APP_VERSION})

@app.route('/')
def index():
    """Renders the main frontend HTML page or returns JSON analysis if format=json and url/raw_html_input are provided."""
    req_format = request.args.get('format', '').lower()
    url = request.args.get('url', '')
    raw_html_input = request.args.get('raw_html_input')

    # Determine if raw HTML input was actually provided and is substantial
    used_raw_html_for_analysis = bool(raw_html_input and raw_html_input.strip())

    if req_format == 'json':
        if not url and not used_raw_html_for_analysis:
            return jsonify({"error": "Either 'url' or 'raw_html_input' is required when format=json."}), 400

        job_id = None
        display_url = url # Default to the provided URL for logging/display

        if used_raw_html_for_analysis:
            # If raw HTML is provided, generate job_id from HTML hash
            html_hash = hashlib.sha256(raw_html_input.encode('utf-8')).hexdigest()
            job_id = f"html_{html_hash}"
            # If a URL is provided with HTML, use it for display/logging, otherwise use a placeholder
            if not display_url:
                display_url = 'urn:html-input:no-url-provided-get'
            print(f"GET /?format=json: Using provided raw HTML for analysis (Job ID: {job_id}). Display URL: {display_url}")
            # No SSRF check needed as we are not scraping
        else: # URL provided, no raw HTML
            # Validate URL for scraping
            if not url.startswith('http://') and not url.startswith('https://'):
                return jsonify({"error": "Invalid URL format. Must start with http:// or https://."}), 400
            # SSRF Prevention for URL scraping
            if not is_safe_url(url):
                return jsonify({"error": "Provided URL is not allowed. Potential security risk."}), 403

            job_id = hashlib.sha256(url.encode('utf-8')).hexdigest()
            print(f"GET /?format=json: Using URL for scraping (Job ID: {job_id}). URL: {url}")


        cache_dir_path = os.path.join(CACHE_DIR, job_id)
        cache_file_path = os.path.join(cache_dir_path, 'analysis.json')
        raw_text_file_path = os.path.join(cache_dir_path, 'raw.txt')

        cached_analysis = None
        if os.path.exists(cache_file_path):
            try:
                with open(cache_file_path, 'r', encoding='utf-8') as f:
                    cached_analysis = json.load(f)

                # Check if cached analysis has an error or is irrelevant and raw.txt exists, implying a previous LLM failure
                if (cached_analysis and cached_analysis.get('full_analysis') and \
                   (cached_analysis['full_analysis'].get('error') or cached_analysis['full_analysis'].get('is_irrelevant'))) \
                   and os.path.exists(raw_text_file_path):
                    print(f"Cached analysis for {display_url} contains an error or is irrelevant but raw text exists. Forcing re-analysis.")
                    cached_analysis = None # Force re-analysis
                elif _version_lt(cached_analysis.get('version', '0.0.0'), CURRENT_APP_VERSION):
                    print(f"Cached version {cached_analysis.get('version', '0.0.0')} is older than current version {CURRENT_APP_VERSION} for {display_url}. Deleting cache and re-analyzing.")
                    shutil.rmtree(cache_dir_path)
                    cached_analysis = None
                else:
                    print(f"Serving cached analysis (version {cached_analysis.get('version', 'N/A')}) for {display_url}")
                    job_statuses[job_id] = {"status": "completed", "result": cached_analysis, "progress": 100}
                    return jsonify(cached_analysis)

            except json.JSONDecodeError as e:
                print(f"Error reading cached JSON for {job_id}: {e}. Cache might be corrupted. Re-analyzing.")
                if os.path.exists(cache_dir_path):
                    shutil.rmtree(cache_dir_path)
                cached_analysis = None
            except Exception as e:
                print(f"An unexpected error occurred during cache check for {job_id}: {e}. Re-analyzing.")
                if os.path.exists(cache_dir_path):
                    shutil.rmtree(cache_dir_path)
                cached_analysis = None

        # Don't restart a job that's already running.
        if job_id not in job_statuses or job_statuses[job_id]["status"] in ["failed", "completed"]:
            job_statuses[job_id] = {"status": "started", "progress": 0}
            executor.submit(analyze_document_task, job_id, display_url, raw_html_input)

        return jsonify({"job_id": job_id, "status": "processing"})

    return render_template('index.html', app_version=CURRENT_APP_VERSION)

@app.route('/search')
def search_page():
    return render_template('search.html', app_version=CURRENT_APP_VERSION)

@app.route('/batch')
def batch_page():
    return render_template('batch.html', app_version=CURRENT_APP_VERSION)

@app.route('/pdf_analyses', methods=['GET'])
def get_pdf_analyses():
    """
    Returns all successfully cached PDF uploads, sorted by most recent first.
    Used by the batch page to populate the Past Uploads section.
    """
    results = []
    for url_hash_dir in os.listdir(CACHE_DIR):
        cache_path = os.path.join(CACHE_DIR, url_hash_dir)
        analysis_json = os.path.join(cache_path, 'analysis.json')
        if not os.path.isdir(cache_path) or not os.path.exists(analysis_json):
            continue
        try:
            with open(analysis_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            url = data.get('url', '')
            if not url.startswith('urn:pdf-upload:'):
                continue
            if data.get('error_message_overall') or \
               (data.get('full_analysis', {}).get('error')):
                continue
            filename = url.replace('urn:pdf-upload:', '')
            results.append({
                "job_id": url_hash_dir,
                "url": url,
                "filename": filename,
                "title": data.get('title', filename),
                "timestamp": data.get('timestamp', 0)
            })
        except Exception:
            continue
    results.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify(results)

@app.route('/about')
def about_page():
    return render_template('about.html', app_version=CURRENT_APP_VERSION)

@app.route('/changelog')
def changelog_page():
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
    raw_html_input = data.get('raw_html_input')
    eligibility_only = bool(data.get('eligibility_only', False))

    if not url:
        return jsonify({"error": "URL is required."}), 400

    # Basic URL validation
    if not url.startswith('http://') and not url.startswith('https://'):
        return jsonify({"error": "Invalid URL format. Must start with http:// or https://."}), 400

    # Flag to determine if raw HTML input was actually provided and is substantial
    used_raw_html_for_analysis = bool(raw_html_input and raw_html_input.strip())

    # --- SSRF Prevention: Validate URL safety before proceeding ---
    if not used_raw_html_for_analysis:
        if not is_safe_url(url):
            return jsonify({"error": "Provided URL is not allowed. Potential security risk."}), 403
    # --- END SSRF Prevention ---

    url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()
    cache_dir_path = os.path.join(CACHE_DIR, url_hash)
    cache_file_path = os.path.join(cache_dir_path, 'analysis.json')
    raw_text_file_path = os.path.join(cache_dir_path, 'raw.txt')

    # Providing raw HTML always forces a fresh analysis (user may have corrected the content).
    force_re_analysis_with_html = used_raw_html_for_analysis

    # Fast-path for eligibility-only requests: bypass full-analysis cache
    if eligibility_only and not force_re_analysis_with_html:
        elig_path = os.path.join(cache_dir_path, 'eligibility.json')
        if os.path.exists(elig_path):
            title = url
            if os.path.exists(cache_file_path):
                try:
                    with open(cache_file_path, 'r', encoding='utf-8') as f:
                        title = json.load(f).get('title', url)
                except Exception:
                    pass
            combined = {
                "version": CURRENT_APP_VERSION, "url": url, "title": title,
                "full_analysis": {"eligibility_only": True},
                "document_raw_text": "", "timestamp": time.time(), "is_irrelevant": False
            }
            job_statuses[url_hash] = {"status": "completed", "result": combined, "progress": 100}
            return jsonify({"job_id": url_hash, "status": "completed", "result": combined})
        if os.path.exists(raw_text_file_path):
            with open(raw_text_file_path, 'r', encoding='utf-8') as f:
                cached_raw = f.read()
            if cached_raw.strip():
                job_statuses[url_hash] = {"status": "started", "progress": 0}
                executor.submit(analyze_document_task, url_hash, url, None, cached_raw, True)
                return jsonify({"job_id": url_hash, "status": "processing"}), 202
        # No eligibility cache and no raw text — fall through to fresh analysis

    cached_analysis = None
    if os.path.exists(cache_file_path) and not force_re_analysis_with_html:
        try:
            with open(cache_file_path, 'r', encoding='utf-8') as f:
                cached_analysis = json.load(f)

            # Check if cached analysis has an error or is irrelevant and raw.txt exists, implying a previous LLM failure
            if (cached_analysis and cached_analysis.get('full_analysis') and \
               (cached_analysis['full_analysis'].get('error') or cached_analysis['full_analysis'].get('is_irrelevant'))) \
               and os.path.exists(raw_text_file_path):
                print(f"Cached analysis for {url} contains an error or is irrelevant but raw text exists. Forcing re-analysis.")
                cached_analysis = None # Force re-analysis
            elif _version_lt(cached_analysis.get('version', '0.0.0'), CURRENT_APP_VERSION):
                print(f"Cached version {cached_analysis.get('version', '0.0.0')} is older than current version {CURRENT_APP_VERSION} for {url}. Deleting cache and re-analyzing.")
                shutil.rmtree(cache_dir_path)
                cached_analysis = None
            else:
                print(f"Serving cached analysis (version {cached_analysis.get('version', 'N/A')}) for {url}")
                job_statuses[url_hash] = {"status": "completed", "result": cached_analysis, "progress": 100}
                if request.args.get('format', '').lower() == 'json':
                    return jsonify(cached_analysis)
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
    executor.submit(analyze_document_task, url_hash, url, raw_html_input, None, eligibility_only)

    if request.args.get('format', '').lower() == 'json':
        return jsonify({"job_id": url_hash, "status": "processing"})
    return jsonify({"job_id": url_hash, "status": "processing"}), 202

@app.route('/analyze/eligibility/<job_id>', methods=['POST'])
def analyze_eligibility(job_id):
    """
    Runs a targeted eligibility check (tenure + transfer student barriers)
    against an already-analyzed document identified by job_id.
    Reads the cached raw.txt so no re-scraping is needed.
    Result is cached to eligibility.json so repeat calls are instant.
    """
    cache_dir_path = os.path.join(CACHE_DIR, job_id)
    raw_text_file_path = os.path.join(cache_dir_path, 'raw.txt')
    eligibility_cache_path = os.path.join(cache_dir_path, 'eligibility.json')

    if not os.path.exists(raw_text_file_path):
        return jsonify({"error": "Document not found. Please analyze a document first."}), 404

    if os.path.exists(eligibility_cache_path):
        with open(eligibility_cache_path, 'r', encoding='utf-8') as f:
            return jsonify(json.load(f))

    with open(raw_text_file_path, 'r', encoding='utf-8') as f:
        document_text = f.read()

    if not document_text.strip():
        return jsonify({"error": "Document text is empty."}), 422

    result = call_gemini_api(document_text, "eligibility_check")

    if result.get("error"):
        return jsonify({"error": result["error"]}), 500

    with open(eligibility_cache_path, 'w', encoding='utf-8') as f:
        json.dump(result, f)

    return jsonify(result)


@app.route('/analyze/pdf', methods=['POST'])
def analyze_pdf():
    """
    Endpoint to analyze an uploaded PDF file.
    Accepts multipart/form-data with a 'pdf_file' field.
    Extracts text with pdfplumber and feeds it into the existing analysis pipeline.
    """
    MAX_PDF_SIZE = 10 * 1024 * 1024  # 10 MB

    if 'pdf_file' not in request.files:
        return jsonify({"error": "No PDF file provided."}), 400

    pdf_file = request.files['pdf_file']

    filename = pdf_file.filename or ''
    if filename == '':
        return jsonify({"error": "No file selected."}), 400

    if not filename.lower().endswith('.pdf'):
        return jsonify({"error": "Only PDF files are accepted."}), 400

    pdf_bytes = pdf_file.read()
    if len(pdf_bytes) > MAX_PDF_SIZE:
        return jsonify({"error": "PDF too large. Maximum size is 10 MB."}), 413

    try:
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            pages_text = [page.extract_text() or "" for page in pdf.pages]
        pdf_text = "\n\n".join(pages_text).strip()
    except Exception as e:
        return jsonify({"error": f"Failed to read PDF: {str(e)}"}), 422

    if not pdf_text:
        return jsonify({"error": "No text could be extracted from this PDF. It may be scanned or image-based."}), 422

    url_hash = "pdf_" + hashlib.sha256(pdf_bytes).hexdigest()
    safe_filename = re.sub(r'[^\w.\-]', '_', filename)
    synthetic_url = f"urn:pdf-upload:{safe_filename}"

    cache_dir_path = os.path.join(CACHE_DIR, url_hash)
    cache_file_path = os.path.join(cache_dir_path, 'analysis.json')
    eligibility_only_pdf = request.form.get('eligibility_only', 'false').lower() == 'true'

    # Fast-path for eligibility-only: bypass full-analysis cache
    if eligibility_only_pdf:
        elig_path = os.path.join(cache_dir_path, 'eligibility.json')
        raw_path = os.path.join(cache_dir_path, 'raw.txt')
        if os.path.exists(elig_path):
            title = safe_filename
            if os.path.exists(cache_file_path):
                try:
                    with open(cache_file_path, 'r', encoding='utf-8') as f:
                        title = json.load(f).get('title', safe_filename)
                except Exception:
                    pass
            combined = {
                "version": CURRENT_APP_VERSION, "url": synthetic_url, "title": title,
                "full_analysis": {"eligibility_only": True},
                "document_raw_text": "", "timestamp": time.time(), "is_irrelevant": False
            }
            job_statuses[url_hash] = {"status": "completed", "result": combined, "progress": 100}
            return jsonify({"job_id": url_hash, "status": "completed", "result": combined})
        # No eligibility cache — run the full task with eligibility_only=True (uses pdf_text)
    else:
        if os.path.exists(cache_file_path):
            try:
                with open(cache_file_path, 'r', encoding='utf-8') as f:
                    cached_analysis = json.load(f)
                if cached_analysis and not (cached_analysis.get('full_analysis', {}).get('error') or cached_analysis.get('full_analysis', {}).get('is_irrelevant')):
                    print(f"Serving cached PDF analysis for {safe_filename}")
                    job_statuses[url_hash] = {"status": "completed", "result": cached_analysis, "progress": 100}
                    return jsonify({"job_id": url_hash, "status": "completed", "result": cached_analysis, "from_cache": True})
            except Exception:
                pass

    if request.form.get('force_new') != 'true':
        conflict = find_cached_pdf_by_filename(safe_filename, url_hash)
        if conflict:
            conflict_job_id, conflict_title = conflict
            return jsonify({
                "filename_conflict": True,
                "conflicting_job_id": conflict_job_id,
                "conflicting_title": conflict_title,
                "filename": safe_filename,
            }), 200

    print(f"Starting PDF analysis for {safe_filename} (Job ID: {url_hash})")
    job_statuses[url_hash] = {"status": "started", "progress": 0}
    executor.submit(analyze_document_task, url_hash, synthetic_url, None, pdf_text, eligibility_only_pdf)

    return jsonify({"job_id": url_hash, "status": "processing"}), 202


@app.route('/status/<job_id>', methods=['GET'])
def get_job_status(job_id):
    """
    Endpoint to check the status of an analysis job.
    Falls back to cache file if not in memory (e.g. after server restart).
    """
    status_info = job_statuses.get(job_id)
    if status_info:
        response_data = {"job_id": job_id, "status": status_info["status"], "progress": status_info.get("progress", 0)}
        if "error" in status_info:
            response_data["error"] = status_info["error"]
        return jsonify(response_data)

    # Fall back to cache file
    cache_file_path = os.path.join(CACHE_DIR, job_id, 'analysis.json')
    if os.path.exists(cache_file_path):
        try:
            with open(cache_file_path, 'r', encoding='utf-8') as f:
                cached = json.load(f)
            if cached.get('error_message_overall') or (cached.get('full_analysis') and cached['full_analysis'].get('error')):
                return jsonify({"job_id": job_id, "status": "failed", "progress": 0, "error": cached.get('error_message_overall', 'Analysis failed.')}), 200
            job_statuses[job_id] = {"status": "completed", "result": cached, "progress": 100}
            return jsonify({"job_id": job_id, "status": "completed", "progress": 100})
        except Exception:
            pass

    return jsonify({"error": "Job ID not found or expired."}), 404

@app.route('/result/<job_id>', methods=['GET'])
def get_job_result(job_id):
    """
    Endpoint to retrieve the full analysis result once completed.
    Falls back to cache file if not in memory (e.g. after server restart).
    """
    status_info = job_statuses.get(job_id)
    if not status_info:
        # Fall back to cache file
        cache_file_path = os.path.join(CACHE_DIR, job_id, 'analysis.json')
        if os.path.exists(cache_file_path):
            try:
                with open(cache_file_path, 'r', encoding='utf-8') as f:
                    cached = json.load(f)
                job_statuses[job_id] = {"status": "completed", "result": cached, "progress": 100}
                return jsonify(cached)
            except Exception:
                pass
        return jsonify({"error": "Job ID not found or expired."}), 404

    if status_info["status"] == "completed":
        return jsonify(status_info["result"])
    elif status_info["status"] == "failed":
        return jsonify({"error": status_info.get("error", "Analysis failed.")}), 500
    else:
        return jsonify({"status": "processing", "message": "Analysis is still in progress."}), 409

@app.route('/recent_analyses', methods=['GET'])
def get_recent_analyses():
    """
    Endpoint to retrieve a list of recent analyses directly from the cache directories.
    Filters out documents that could not be scraped or analyzed successfully.
    Returns up to 5 most recent analyses with their URL and title.
    """
    recent_items = []
    all_cached_analyses = []

    # Iterate through all cached analysis directories
    for url_hash_dir in os.listdir(CACHE_DIR):
        cache_path = os.path.join(CACHE_DIR, url_hash_dir)
        analysis_json_file_path = os.path.join(cache_path, 'analysis.json')

        if os.path.isdir(cache_path) and os.path.exists(analysis_json_file_path):
            try:
                with open(analysis_json_file_path, 'r', encoding='utf-8') as f:
                    analysis_data = json.load(f)

                # Determine if the analysis was a failed scrape or had an overall error or was irrelevant
                is_failed_scrape_or_irrelevant = analysis_data.get('error_message_overall') or \
                                                 (analysis_data.get('full_analysis') and \
                                                  (analysis_data['full_analysis'].get('error') or \
                                                   analysis_data['full_analysis'].get('is_irrelevant')))

                # Filter out entries that represent failed scrapes, generic titles, or irrelevant content
                if analysis_data.get('title') == 'N/A' or \
                   analysis_data.get('title') == 'Untitled Document' or \
                   is_failed_scrape_or_irrelevant:
                    continue # Skip this entry if it's an unscraped/failed/irrelevant document

                all_cached_analyses.append({
                    "url": analysis_data.get('url', ''),
                    "title": analysis_data.get('title', 'Untitled Document'),
                    "timestamp": analysis_data.get('timestamp', 0),
                    "job_id": url_hash_dir
                })
            except (json.JSONDecodeError, Exception) as e:
                print(f"Error reading cached analysis JSON {analysis_json_file_path}: {e}. Skipping.")
                continue

    # Sort by timestamp, most recent first
    all_cached_analyses.sort(key=lambda x: x.get('timestamp', 0), reverse=True)

    # Get top 5 (or fewer if less than 5)
    recent_items = all_cached_analyses[:5]

    return jsonify(recent_items)

@app.route('/cache/<job_id>', methods=['DELETE'])
def delete_cached_analysis(job_id):
    """Deletes a cached analysis directory and removes it from job_statuses."""
    # Sanitize job_id to prevent path traversal
    if '/' in job_id or '\\' in job_id or '..' in job_id:
        return jsonify({"error": "Invalid job ID."}), 400

    cache_dir_path = os.path.join(CACHE_DIR, job_id)
    if not os.path.exists(cache_dir_path):
        return jsonify({"error": "Cache not found."}), 404

    try:
        shutil.rmtree(cache_dir_path)
        job_statuses.pop(job_id, None)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/search_cached', methods=['GET'])
def search_cached():
    """
    Searches through cached analysis results directly from the cache directories
    by URL, title, or company name.
    Includes all documents, marking broken, outdated, or irrelevant ones.
    """
    query = request.args.get('query', '').lower()
    results = []

    for url_hash_dir in os.listdir(CACHE_DIR):
        cache_path = os.path.join(CACHE_DIR, url_hash_dir)
        analysis_json_file_path = os.path.join(cache_path, 'analysis.json')

        if not os.path.isdir(cache_path) or not os.path.exists(analysis_json_file_path):
            continue

        try:
            with open(analysis_json_file_path, 'r', encoding='utf-8') as f:
                analysis_data = json.load(f)

            url            = analysis_data.get('url', '')
            title          = analysis_data.get('title', 'Untitled Document')
            timestamp      = analysis_data.get('timestamp', 0)
            cached_version = analysis_data.get('version', '0.0.0')

            # is_irrelevant is stored both at the top level and nested inside full_analysis
            # (older cache entries only have the nested form).
            is_irrelevant = (
                analysis_data.get('is_irrelevant', False)
                or analysis_data.get('full_analysis', {}).get('is_irrelevant', False)
            )

            # Irrelevant-title rejections store a specific error string; don't flag those as "broken".
            is_broken = (
                bool(
                    analysis_data.get('error_message_overall')
                    or (analysis_data.get('full_analysis') and analysis_data['full_analysis'].get('error'))
                )
                and "does not appear to be a legal policy" not in analysis_data.get('error_message_overall', '')
            )

            is_outdated = _version_lt(cached_version, CURRENT_APP_VERSION)

            company_name = (_extract_company_name_from_url(url) or '').lower()

            if query in url.lower() or query in title.lower() or query in company_name:
                results.append({
                    "url": url,
                    "title": title,
                    "timestamp": timestamp,
                    "version": cached_version,
                    "is_outdated": is_outdated,
                    "is_broken": is_broken,
                    "is_irrelevant": is_irrelevant,
                    "job_id": url_hash_dir,
                })

        except (json.JSONDecodeError, Exception) as e:
            print(f"Error reading cached analysis JSON {analysis_json_file_path}: {e}. Treating as broken.")
            file_url = "N/A"
            file_title = f"Corrupted Entry ({url_hash_dir})"
            try:
                file_url = urllib.parse.unquote(url_hash_dir.split('_', 1)[-1])
            except Exception:
                pass

            results.append({
                "url": file_url,
                "title": file_title,
                "timestamp": 0,
                "version": "0.0.0",
                "is_outdated": True,
                "is_broken": True,
                "is_irrelevant": True,
            })


    # Two-pass stable sort: first by recency, then push broken entries to the bottom.
    # Python's sort is stable, so broken entries remain recency-ordered among themselves.
    results.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
    results.sort(key=lambda x: x.get('is_broken', False))
    return jsonify(results)


if __name__ == '__main__':
    # For local development, you can run: python app.py
    # In a production Gunicorn/WSGI environment, the server will handle this.
    app.run(debug=True, host='127.0.0.1', port=5000)
