import os
import json
import hashlib
import time
import urllib.parse
import re

# Configuration
CACHE_ROOT_DIR = './cache/TOSCheck'
CONTRACTS_FILE = os.path.join(CACHE_ROOT_DIR, 'contracts.json')

def _extract_company_name_from_url(url):
    """
    Extracts and cleans a potential company name from a URL's hostname.
    Copied from app.py for consistency.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname

        if not hostname:
            return None

        domain_parts = hostname.replace('www.', '').split('.')

        if len(domain_parts) >= 2:
            if len(domain_parts) >= 3 and (domain_parts[-2] + '.' + domain_parts[-1]) in ['co.uk', 'com.au', 'org.uk', 'net.au']:
                company_name = domain_parts[-3]
            else:
                company_name = domain_parts[-2]

            company_name = re.sub(r'[^a-zA-Z]+$', '', company_name)

            if company_name.lower().endswith('ai'):
                company_name = company_name[:-2].capitalize() + ' AI'
            else:
                company_name = company_name.capitalize()

            return company_name
        return None
    except Exception as e:
        print(f"Error extracting company name from URL {url}: {e}")
        return None

def populate_contracts_json_from_cache():
    """
    Populates contracts.json by reading analysis.json files from cache directories.
    It will add/update entries in contracts.json based on the latest analysis.json data.
    """
    print(f"Starting to populate {CONTRACTS_FILE} from cache...")
    
    all_contract_entries = []
    if os.path.exists(CONTRACTS_FILE):
        try:
            with open(CONTRACTS_FILE, 'r', encoding='utf-8') as f:
                all_contract_entries = json.load(f)
                if not isinstance(all_contract_entries, list):
                    print(f"Warning: {CONTRACTS_FILE} content is not a list. Starting with an empty list.")
                    all_contract_entries = []
        except (json.JSONDecodeError, Exception) as e:
            print(f"Warning: Could not read existing {CONTRACTS_FILE}: {e}. Starting with an empty list.")
            all_contract_entries = []

    # Create a dictionary for quick lookup by URL
    existing_urls_map = {entry.get('company_url'): entry for entry in all_contract_entries if entry.get('company_url')}
    
    updated_count = 0
    new_count = 0
    processed_dirs = 0

    # List all items in CACHE_ROOT_DIR
    # Ensure CACHE_ROOT_DIR exists before listing its contents
    if not os.path.exists(CACHE_ROOT_DIR):
        print(f"Error: Cache root directory not found at {CACHE_ROOT_DIR}")
        print(f"Successfully updated {CONTRACTS_FILE} with {new_count} new entries and {updated_count} updated entries.")
        return

    for item_name in os.listdir(CACHE_ROOT_DIR):
        job_dir_path = os.path.join(CACHE_ROOT_DIR, item_name)
        analysis_file_path = os.path.join(job_dir_path, 'analysis.json')
        raw_html_file_path = os.path.join(job_dir_path, 'html.txt')  # <-- Use html.txt

        # Only process if it's a directory and contains an analysis.json
        if os.path.isdir(job_dir_path) and os.path.exists(analysis_file_path):
            processed_dirs += 1
            print(f"\n--- Processing cache directory: {item_name} ---")
            try:
                with open(analysis_file_path, 'r', encoding='utf-8') as f:
                    analysis_data = json.load(f)

                url = analysis_data.get('url')
                title = analysis_data.get('title', 'Untitled Document')
                manual_html_provided = analysis_data.get('manual_html_provided', False)
                timestamp = analysis_data.get('timestamp', time.time())
                
                if not url:
                    print(f"Skipping {item_name}: 'url' not found in analysis.json. Content: {analysis_data.keys()}")
                    continue

                # Read raw HTML content from html.txt
                document_raw_html = ""
                if os.path.exists(raw_html_file_path):
                    try:
                        with open(raw_html_file_path, 'r', encoding='utf-8') as rf:
                            document_raw_html = rf.read()
                        print(f"Read html.txt ({len(document_raw_html)} chars) for URL: {url}")
                    except Exception as e:
                        print(f"Error reading html.txt for {item_name}: {e}")
                else:
                    print(f"Warning: html.txt not found for {item_name}. Raw HTML will be empty.")

                company_name = analysis_data.get('company_name')
                if not company_name:
                    company_name = _extract_company_name_from_url(url) or "N/A"

                new_entry = {
                    "company_name": company_name,
                    "company_url": url,
                    "document_title": title,
                    "manual_html_provided": manual_html_provided,
                    "document_raw_html": document_raw_html,  # <-- Store raw HTML
                    "timestamp": timestamp,
                    "analysis_job_id": item_name # Store the directory name (job_id) for reference
                }

                if url in existing_urls_map:
                    old_entry = existing_urls_map[url]
                    # Check if the new entry is genuinely newer or has different content
                    # Compare relevant fields to decide if an update is needed
                    if (new_entry['timestamp'] > old_entry.get('timestamp', 0) or
                        new_entry['document_raw_html'] != old_entry.get('document_raw_html') or
                        new_entry['document_title'] != old_entry.get('document_title') or
                        new_entry['manual_html_provided'] != old_entry.get('manual_html_provided')):
                        
                        # Find and replace the old entry in the original list
                        for i, entry in enumerate(all_contract_entries):
                            if entry.get('company_url') == url:
                                all_contract_entries[i] = new_entry
                                updated_count += 1
                                print(f"Updated existing entry for URL: {url}")
                                break
                    else:
                        print(f"Entry for URL {url} already exists and is up-to-date.")
                else:
                    all_contract_entries.append(new_entry)
                    existing_urls_map[url] = new_entry # Add to map for future checks in this run
                    new_count += 1
                    print(f"Added new entry for URL: {url}")

            except (json.JSONDecodeError, Exception) as e:
                print(f"Error processing {analysis_file_path}: {e}. Skipping this entry.")
                continue
        elif item_name == 'contracts.json':
            # Skip contracts.json itself if it's in the root cache directory
            print(f"Skipping {item_name}: It's the contracts.json file itself.")
            continue
        elif os.path.isdir(job_dir_path):
            print(f"Skipping directory {item_name}: No analysis.json found.")
        else:
            print(f"Skipping item {item_name}: Not a directory.")


    # Write the updated list back to contracts.json
    try:
        # Sort entries by timestamp before writing, most recent first
        all_contract_entries.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
        with open(CONTRACTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(all_contract_entries, f, ensure_ascii=False, indent=4)
        print(f"\n--- Population Complete ---")
        print(f"Total directories processed: {processed_dirs}")
        print(f"Successfully updated {CONTRACTS_FILE} with {new_count} new entries and {updated_count} updated entries.")
    except Exception as e:
        print(f"Error writing to {CONTRACTS_FILE}: {e}")

if __name__ == "__main__":
    populate_contracts_json_from_cache()