import requests
from bs4 import BeautifulSoup

from app import is_safe_url
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
        #'Accept-Encoding': 'gzip, deflate, br',
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
        #for key, value in response.headers.items():
        #    print(f"{key}: {value}")
        # Explicitly set encoding to UTF-8 if it's not already, or if it's detected incorrectly
        #response.encoding = 'utf-8' # Force UTF-8 decoding

        soup = BeautifulSoup(response.text, 'html.parser')

        print(f"HTML content for {url}: {response.text}")
        #print(f"soop: {soup}   ")
        # Extract title
        if soup.title and soup.title.string:
            page_title = soup.title.string.strip()
        elif soup.find('h1') and soup.find('h1').string:
            page_title = soup.find('h1').string.strip()


        # Attempt to extract main content. This is a heuristic and might need refinement
        # for different website structures.
        main_content = soup.find('body') or soup.find('article') or soup.find('main')

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
    