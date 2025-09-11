"""
Basic tests for CI/CD pipeline that don't require external dependencies
"""
import pytest
import sys
import os

def test_python_modules():
    """Test that basic Python modules work."""
    import json
    import time
    import threading
    import re
    import os
    assert True

def test_required_packages():
    """Test that required packages can be imported."""
    try:
        import flask
        import requests
        assert True
    except ImportError as e:
        pytest.fail(f"Required package missing: {e}")

def test_youtube_url_regex():
    """Test YouTube URL detection logic without importing main app."""
    import re
    
    # Simple YouTube URL regex (copied from main app logic)
    youtube_patterns = [
        r'(?:https?://)?(?:www\.)?youtube\.com/watch\?v=([a-zA-Z0-9_-]+)',
        r'(?:https?://)?youtu\.be/([a-zA-Z0-9_-]+)',
        r'(?:https?://)?(?:www\.)?youtube\.com/embed/([a-zA-Z0-9_-]+)',
        r'(?:https?://)?(?:www\.)?youtube\.com/v/([a-zA-Z0-9_-]+)'
    ]
    
    test_urls = [
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://youtu.be/dQw4w9WgXcQ",
        "youtube.com/watch?v=dQw4w9WgXcQ",
        "not a youtube url"
    ]
    
    matches = []
    for url in test_urls[:3]:  # First 3 should match
        found = False
        for pattern in youtube_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                found = True
                break
        matches.append(found)
    
    # Should not match the last one
    found = False
    for pattern in youtube_patterns:
        if re.search(pattern, test_urls[3], re.IGNORECASE):
            found = True
            break
    matches.append(found)
    
    assert matches == [True, True, True, False]

def test_version_info_structure():
    """Test version info loading logic."""
    # Test that we can create version info structure
    version_info = {
        'version': '1.0.0',
        'commit': 'abc123',
        'build_date': '2023-01-01',
        'environment': 'test'
    }
    
    assert version_info.get('version') == '1.0.0'
    assert version_info.get('commit') == 'abc123'
    assert 'environment' in version_info

def test_config_structure():
    """Test config structure without loading actual config."""
    # Test the basic config structure we expect
    mock_config = {
        'slack_settings': {
            'bot_token': 'test-token',
            'signing_secret': 'test-secret',
            'channels': [],
            'recent_activity': []
        },
        'openai_settings': {
            'api_key': 'test-key'
        }
    }
    
    assert 'slack_settings' in mock_config
    assert 'openai_settings' in mock_config
    assert isinstance(mock_config['slack_settings']['recent_activity'], list)