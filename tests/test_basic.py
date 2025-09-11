#!/usr/bin/env python3
"""
Basic tests for StreamSnap application
"""
import pytest
import os

@pytest.mark.skipif(
    not os.getenv('FLASK_SECRET_KEY'), 
    reason="Requires environment variables for app initialization"
)
def test_app_import():
    """Test that the main application module can be imported."""
    try:
        import streamsnap_app
        assert True
    except ImportError:
        pytest.fail('Could not import main application module')

@pytest.mark.skipif(
    not os.getenv('FLASK_SECRET_KEY'), 
    reason="Requires environment variables for app initialization"
)
def test_flask_app_creation():
    """Test that Flask app can be created."""
    try:
        import streamsnap_app
        app = streamsnap_app.app
        assert app is not None
        assert app.name == 'streamsnap_app'
    except Exception as e:
        pytest.fail(f'Could not create Flask app: {str(e)}')

@pytest.mark.skipif(
    not os.getenv('FLASK_SECRET_KEY'), 
    reason="Requires environment variables for app initialization"
)
def test_health_endpoint_exists():
    """Test that health endpoint is defined."""
    try:
        import streamsnap_app
        # Check if health route exists
        rules = [rule.rule for rule in streamsnap_app.app.url_map.iter_rules()]
        assert '/health' in rules
    except Exception as e:
        pytest.fail(f'Health endpoint test failed: {str(e)}')