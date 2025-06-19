import pytest
import json
import os
import shutil # Still needed for patching, if app.py uses it at module level (not for rmtree now)
import time
import requests
from unittest import mock

# --- CRITICAL IMPORTS FOR MODULE ACCESS ---
# Import the 'app' module directly to access its global functions.
import app 
# No need to import the 'app' Flask instance or job_statuses if we're not testing routes directly.
# No need to import CACHE_DIR, VERSION_FILE, load_current_app_version if not testing related Flask logic.
# We explicitly import the functions we intend to test (or mock parts of).
from app import call_gemini_api, get_document_text, get_gemini_api_key

# --- END CRITICAL IMPORTS ---

# --- Helper Mocks for API Responses ---
class MockResponse:
    """A helper class to mock requests.Response objects."""
    def __init__(self, json_data, status_code=200, text="", headers=None, encoding='utf-8'):
        self._json_data = json_data
        self.status_code = status_code
        self.text = text if text else (json.dumps(json_data) if json_data is not None else "")
        self.headers = headers if headers is not None else {'Content-Type': 'application/json'}
        self.encoding = encoding

    def json(self):
        if self._json_data is None:
            raise json.JSONDecodeError("No JSON data to decode", self.text, 0)
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP Error: {self.status_code}", response=self)
# --- END Helper Mocks ---


# Define a dummy URL for testing (still useful for the scraping function)
TEST_URL = "http://example.com/terms-of-service"
# TEST_URL_HASH is no longer needed as we're not testing Flask routes or caching jobs directly.


# --- Pytest Fixtures ---

@pytest.fixture
def mocker_fixture(mocker):
    """Provides the pytest-mock mocker object."""
    return mocker

@pytest.fixture
def mock_gemini_api_key_fixture(mocker_fixture):
    """Mocks the get_gemini_api_key function to return a dummy key."""
    # Patch the function within the 'app' module
    mocker_fixture.patch('app.get_gemini_api_key', return_value="TEST_API_KEY_123") 


# --- Unit Tests for Core Functions ---

def test_get_document_text_success(mocker_fixture):
    """Test successful HTML fetching and text extraction."""
    mock_html = '<html><head><title>Test Page</title></head><body><p>This is a paragraph.</p><h1>A Heading</h1><ul><li>Item 1</li><li>Item 2</li></ul></body></html>'
    mock_response = MockResponse(json_data=None, text=mock_html)
    mock_requests_get = mocker_fixture.patch('requests.get', return_value=mock_response) 

    result = app.get_document_text(TEST_URL) # Call function directly via app module
    
    mock_requests_get.assert_called_once_with( 
        TEST_URL,
        headers=mock.ANY,
        timeout=15
    )
    expected_text = "This is a paragraph. A Heading Item 1 Item 2"
    assert result == expected_text


def test_get_document_text_http_error(mocker_fixture):
    """Test handling of HTTP errors during fetching."""
    mock_requests_get = mocker_fixture.patch('requests.get', side_effect=requests.exceptions.HTTPError("404 Not Found", response=MockResponse(None, 404))) 
    result = app.get_document_text(TEST_URL) # Call function directly via app module
    assert result is None
    mock_requests_get.assert_called_once() 


def test_get_document_text_connection_error(mocker_fixture):
    """Test handling of connection errors during fetching."""
    mock_requests_get = mocker_fixture.patch('requests.get', side_effect=requests.exceptions.ConnectionError("Network down")) 
    result = app.get_document_text(TEST_URL) # Call function directly via app module
    assert result is None
    mock_requests_get.assert_called_once() 


def test_get_document_text_no_main_content_in_body(mocker_fixture):
    """Test case where main content (body) is found but contains no extractable text elements."""
    mock_html = '<html><head></head><body><span>Just some span.</span></body></html>'
    mock_response = MockResponse(json_data=None, text=mock_html)
    mock_requests_get = mocker_fixture.patch('requests.get', return_value=mock_response) 
    result = app.get_document_text(TEST_URL) # Call function directly via app module
    assert result == "" # Expect empty string because body is found but no <p>, <h1> etc.


def test_call_gemini_api_summary_success(mocker_fixture, mock_gemini_api_key_fixture):
    """Test successful Gemini API call for summary."""
    test_text = "This is a long document about privacy."
    mock_gemini_json_response = {
        "candidates": [{
            "content": {
                "parts": [{"text": json.dumps({"summary": "A brief summary of privacy document."})}]
            }
        }]
    }
    mock_requests_post = mocker_fixture.patch('requests.post', return_value=MockResponse(mock_gemini_json_response)) 

    result = app.call_gemini_api(test_text, "summary") # Call function directly via app module
    
    assert result == {"summary": "A brief summary of privacy document."}
    mock_requests_post.assert_called_once() 
    args, kwargs = mock_requests_post.call_args 
    assert args[0].startswith("https://generativelanguage.googleapis.com/")
    
    prompt_sent = kwargs['json']['contents'][0]['parts'][0]['text']
    assert "Summarize the following legal document concisely and in consumer-friendly language." in prompt_sent
    assert "Focus on the most important aspects for an average user." in prompt_sent
    assert "Use **bold** for key terms and concepts, and if there are multiple points, use a markdown bulleted list." in prompt_sent
    assert f"Document Text:\n{test_text}" in prompt_sent

    assert kwargs['json']['generationConfig']['responseMimeType'] == "application/json"
    assert kwargs['json']['generationConfig']['responseSchema'] == {
        "type": "OBJECT",
        "properties": {
            "summary": {"type": "STRING"}
        },
        "required": ["summary"]
    }


def test_call_gemini_api_data_collection_success(mocker_fixture, mock_gemini_api_key_fixture):
    """Test successful Gemini API call for data_collection."""
    test_text = "We collect email and name for marketing purposes."
    mock_gemini_json_response = {
        "candidates": [{
            "content": {
                "parts": [{"text": json.dumps([{"dataType": "email", "purpose": "marketing"}, {"dataType": "name", "purpose": "identification"}])}]
            }
        }]
    }
    mock_requests_post = mocker_fixture.patch('requests.post', return_value=MockResponse(mock_gemini_json_response)) 

    result = app.call_gemini_api(test_text, "data_collection") # Call function directly via app module
    assert result == [{"dataType": "email", "purpose": "marketing"}, {"dataType": "name", "purpose": "identification"}]
    mock_requests_post.assert_called_once()


def test_call_gemini_api_missing_key(mocker_fixture):
    """Test Gemini API call when key is missing."""
    mocker_fixture.patch('app.get_gemini_api_key', return_value=None) 
    result = app.call_gemini_api("some text", "summary") # Call function directly via app module
    assert "error" in result
    assert "Gemini API Key not configured." in result["error"]
    mock_requests_post = mocker_fixture.patch('requests.post') # Patch requests.post to get a mock object even if not called
    mock_requests_post.assert_not_called() 


def test_call_gemini_api_invalid_prompt_type(mocker_fixture, mock_gemini_api_key_fixture):
    """Test Gemini API call with an invalid prompt type."""
    result = app.call_gemini_api("some text", "unknown_type") # Call function directly via app module
    assert "error" in result
    assert "Invalid prompt type: unknown_type" in result["error"]
    mock_requests_post = mocker_fixture.patch('requests.post') # Patch requests.post to get a mock object
    mock_requests_post.assert_not_called() 


def test_call_gemini_api_malformed_response_json(mocker_fixture, mock_gemini_api_key_fixture):
    """Test handling of malformed JSON response from Gemini API."""
    mock_requests_post = mocker_fixture.patch('requests.post', return_value=MockResponse(json_data=None, text="this is not json")) # Store the mock
    
    result = app.call_gemini_api("some text", "summary") # Call function directly via app module
    assert "error" in result
    assert "Failed to parse Gemini API response." in result["error"]
    mock_requests_post.assert_called_once() # Ensure it was called


def test_call_gemini_api_unexpected_response_structure(mocker_fixture, mock_gemini_api_key_fixture):
    """Test handling of unexpected structure in Gemini API response."""
    mock_gemini_json_response = {"candidates": []}
    mock_requests_post = mocker_fixture.patch('requests.post', return_value=MockResponse(mock_gemini_json_response)) # Store the mock
    
    result = app.call_gemini_api("some text", "summary") # Call function directly via app module
    assert "error" in result
    assert "Unexpected Gemini API response structure." in result["error"]
    mock_requests_post.assert_called_once() # Ensure it was called
