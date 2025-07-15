# test_playwright_etsy.py
import os
import sys
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

# Define a placeholder for the app's cache directory, not strictly needed for this test
# but good practice if you were to integrate it more deeply.
CACHE_DIR = './cache/TOSCheck'
os.makedirs(CACHE_DIR, exist_ok=True) # Ensure cache directory exists for consistency

def _get_document_text_playwright(url):
    """
    Fetches HTML content using Playwright for pages that require JavaScript rendering.
    This is a direct copy of the function from app.py for standalone testing.
    Returns a tuple: (text_content, page_title, raw_html_content)
    """
    print(f"Attempting to scrape with Playwright: {url}")
    page_title = "Untitled Document (Playwright)"
    raw_html_content = ""
    text_content = ""

    try:
        with sync_playwright() as p:
            # Launch Chromium in headless mode for background execution
            # Set `headless=False` if you want to see the browser UI during testing
            browser = p.chromium.launch(headless=False)
            page = browser.new_page()
            page.set_default_timeout(600000) # 60 seconds timeout for page operations

            # Navigate to the URL
            page.goto(url)

            # Wait for the network to be idle, indicating most content has loaded
            # This is crucial for pages that load content dynamically via JavaScript
            page.wait_for_load_state('networkidle')

            # Get the page title
            page_title = page.title() if page.title() else page_title

            # Get the full HTML content of the page
            raw_html_content = page.content()

            # Use BeautifulSoup to parse the HTML and extract text
            soup = BeautifulSoup(raw_html_content, 'html.parser')

            # Attempt to extract main content. This heuristic might need refinement
            # for different website structures. It looks for common content containers.
            main_content = soup.find('body') or soup.find('article') or soup.find('main')

            if not main_content:
                text_content = "Could not extract main content from the page using Playwright."
            else:
                # Extract text from paragraphs, headings, and list items
                paragraphs = main_content.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li'])
                text_content = "\n".join([elem.get_text(separator=" ", strip=True) for elem in paragraphs])
                # Basic sanitization to remove excessive whitespace
                text_content = ' '.join(text_content.split())

            browser.close()
            return text_content, page_title, raw_html_content

    except Exception as e:
        print(f"Error fetching URL with Playwright {url}: {e}")
        return f"Error fetching URL with Playwright: {e}", page_title, raw_html_content

if __name__ == "__main__":
    # The URL for Etsy's Terms of Use
    etsy_url = "https://openai.com/policies/row-terms-of-use/"

    print(f"--- Starting Playwright test for: {etsy_url} ---")

    # Call the Playwright scraping function
    text, title, html = _get_document_text_playwright(etsy_url)

    print("\n--- Scraped Page Title ---")
    print(title)

    print("\n--- Extracted Text Content (first 100000 characters) ---")
    # Print only a portion of the text to avoid overwhelming the console
    print(text[:100000] + ("..." if len(text) > 100000 else ""))

    print("\n--- Raw HTML Content (first 100000 characters) ---")
    # Print only a portion of the HTML
    print(html[:100000] + ("..." if len(html) > 100000 else ""))

    if "Error fetching URL with Playwright" in text:
        print("\n--- Playwright scraping failed! ---")
    elif len(text) < 100: # A simple check for very little content
        print("\n--- Warning: Playwright scraped very little content. ---")
    else:
        print("\n--- Playwright scraping appears successful! ---")

    print("\n--- Test Finished ---")
