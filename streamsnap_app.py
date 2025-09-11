from flask import Flask, render_template, jsonify, request, flash, redirect, url_for
import os
import json
import time
import yaml
import re
import yt_dlp
# OpenAI imports moved to function level to avoid initialization issues
from pathlib import Path
import tempfile
import traceback
import json
import hmac
import hashlib
import threading

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-key-change-in-production')

# Template filters for dashboard
@app.template_filter('timestamp_to_date')
def timestamp_to_date(timestamp):
    """Convert timestamp to readable date."""
    if not timestamp:
        return 'Never'
    try:
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M')
    except:
        return 'Invalid date'

@app.template_filter('timestamp_to_relative')  
def timestamp_to_relative(timestamp):
    """Convert timestamp to relative time (e.g., '2 hours ago')."""
    if not timestamp:
        return 'Unknown'
    try:
        from datetime import datetime
        import time as time_module
        
        now = time_module.time()
        diff = now - timestamp
        
        if diff < 60:
            return 'Just now'
        elif diff < 3600:
            mins = int(diff / 60)
            return f'{mins} minute{"s" if mins != 1 else ""} ago'
        elif diff < 86400:
            hours = int(diff / 3600)  
            return f'{hours} hour{"s" if hours != 1 else ""} ago'
        else:
            days = int(diff / 86400)
            return f'{days} day{"s" if days != 1 else ""} ago'
    except:
        return 'Unknown time'

@app.template_filter('duration_format')
def duration_format(seconds):
    """Format duration in seconds to readable format."""
    if not seconds:
        return '0s'
    try:
        seconds = int(seconds)
        if seconds < 60:
            return f'{seconds}s'
        elif seconds < 3600:
            mins = seconds // 60
            secs = seconds % 60
            return f'{mins}m {secs}s' if secs else f'{mins}m'
        else:
            hours = seconds // 3600
            mins = (seconds % 3600) // 60
            return f'{hours}h {mins}m' if mins else f'{hours}h'
    except:
        return 'Unknown duration'

START_TIME = time.time()

# Global URL deduplication tracking
# Key: clean video URL, Value: timestamp when processing started
processing_urls = {}

# Global processing threads tracking for safe restart
# Key: thread_id, Value: {'thread': thread_object, 'url': video_url, 'started': timestamp, 'user_id': user_id}
active_threads = {}
shutdown_requested = False

def register_processing_thread(thread_id, thread_obj, video_url, user_id=None):
    """Register an active processing thread for safe restart tracking."""
    global active_threads
    active_threads[thread_id] = {
        'thread': thread_obj,
        'url': video_url,
        'started': time.time(),
        'user_id': user_id or 'unknown'
    }
    print(f"📝 Registered processing thread {thread_id}: {video_url}")

def unregister_processing_thread(thread_id):
    """Unregister a completed processing thread."""
    global active_threads
    if thread_id in active_threads:
        url = active_threads[thread_id]['url']
        del active_threads[thread_id]
        print(f"✅ Unregistered completed thread {thread_id}: {url}")

def get_active_processing_status():
    """Get current processing status for dashboard and safe restart."""
    
    # Clean up finished threads
    finished_threads = []
    for thread_id, info in active_threads.items():
        if not info['thread'].is_alive():
            finished_threads.append(thread_id)
    
    for thread_id in finished_threads:
        unregister_processing_thread(thread_id)
    
    # Return current active status
    active_count = len(active_threads)
    active_details = []
    
    for thread_id, info in active_threads.items():
        duration = time.time() - info['started']
        active_details.append({
            'thread_id': thread_id,
            'url': info['url'],
            'user_id': info['user_id'],
            'duration': duration,
            'started': info['started']
        })
    
    return {
        'active_count': active_count,
        'active_threads': active_details,
        'can_safely_restart': active_count == 0,
        'shutdown_requested': shutdown_requested
    }

def request_graceful_shutdown():
    """Request graceful shutdown - stop accepting new work and wait for current tasks."""
    global shutdown_requested
    shutdown_requested = True
    print("🛑 Graceful shutdown requested - no new processing will start")
    
    return get_active_processing_status()

def wait_for_safe_restart(max_wait_seconds=300):
    """Wait for all active processing to complete before allowing restart."""
    
    print("⏳ Waiting for active processing to complete before restart...")
    start_time = time.time()
    
    while time.time() - start_time < max_wait_seconds:
        status = get_active_processing_status()
        
        if status['can_safely_restart']:
            print("✅ All processing complete - safe to restart")
            return True
            
        print(f"⏳ Waiting for {status['active_count']} active threads to complete...")
        time.sleep(5)
    
    print(f"⚠️ Timeout after {max_wait_seconds}s - some threads may still be active")
    return False

def load_version_info():
    """Load version information from build or fallback to placeholder."""
    try:
        # Try to load build-generated version first
        if os.path.exists('version_build.json'):
            with open('version_build.json', 'r') as f:
                return json.load(f)
        # Fallback to placeholder version
        elif os.path.exists('version.json'):
            with open('version.json', 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading version info: {e}")
    
    # Ultimate fallback
    return {
        "version": "unknown",
        "commit": "unknown", 
        "build_date": "unknown",
        "environment": "unknown"
    }

@app.route('/health')
def health():
    """Standardized health check endpoint."""
    version_info = load_version_info()
    
    health_status = {
        'status': 'healthy',
        'service': 'streamsnap',
        'version': version_info.get('version', 'unknown'),
        'commit': version_info.get('commit', 'unknown'),
        'build_date': version_info.get('build_date', 'unknown'),
        'uptime': int(time.time() - START_TIME),
        'environment': version_info.get('environment', 'unknown'),
        'checks': {}
    }
    
    return jsonify(health_status), 200

@app.route('/health/watchtower')
def health_watchtower():
    """Watchtower-specific health check that prevents updates during active processing."""
    version_info = load_version_info()
    processing_status = get_active_processing_status()
    
    base_health = {
        'service': 'streamsnap',
        'version': version_info.get('version', 'unknown'),
        'commit': version_info.get('commit', 'unknown'),
        'uptime': int(time.time() - START_TIME),
        'active_threads': processing_status['active_count'],
        'can_safely_restart': processing_status['can_safely_restart']
    }
    
    # Return 503 (Service Unavailable) if there's active processing or shutdown requested
    # This tells Watchtower to wait before updating
    if not processing_status['can_safely_restart']:
        return jsonify({
            **base_health,
            'status': 'busy',
            'message': f'Active processing in progress - update blocked ({processing_status["active_count"]} threads)',
        }), 503
    
    return jsonify({
        **base_health,
        'status': 'healthy',
        'message': 'Safe to update'
    }), 200

@app.route('/test-canvas-api')
def test_canvas_api():
    """Test endpoint to debug Canvas API directly (no Slack verification)"""
    try:
        config = load_config()
        
        test_content = """# 📺 Canvas Test - StreamSnap Functionality

**Duration:** 5:30
**Video:** https://www.youtube.com/watch?v=test123
**Processed by:** StreamSnap AI

## 📝 Summary

This is a test of the StreamSnap Canvas creation functionality.

## Test Summary

This Canvas was created to verify that the Canvas API is working properly with your Slack workspace.

**Key Points:**
- Canvas creation: Testing
- Markdown formatting: Supported  
- Fallback messaging: Available

## Next Steps

If this works, Canvas is properly configured."""

        print("🧪 Direct Canvas API test starting...")
        canvas_id = create_slack_canvas(test_content, config)
        
        if canvas_id:
            print(f"🧪 Canvas created: {canvas_id}, now posting notification...")
            # Create test video info for notification
            test_video_info = {
                'title': 'Canvas Test - StreamSnap Functionality',
                'duration': '5:30',
                'url': 'https://www.youtube.com/watch?v=test123'
            }
            notification_success = post_canvas_notification(test_video_info, canvas_id, config)
            
            if notification_success:
                return jsonify({
                    'status': 'success',
                    'message': 'Canvas created and notification posted successfully',
                    'canvas_id': canvas_id,
                    'notification_posted': True
                })
            else:
                return jsonify({
                    'status': 'partial_success',
                    'message': 'Canvas created but failed to post notification',
                    'canvas_id': canvas_id,
                    'notification_posted': False
                })
        else:
            return jsonify({
                'status': 'failed',
                'message': 'Canvas creation failed',
                'canvas_id': None,
                'shared': False
            }), 500
            
    except Exception as e:
        print(f"❌ Canvas test endpoint error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/debug-channels')
def debug_channels():
    """Debug endpoint to check bot's channel access"""
    try:
        from slack_sdk import WebClient
        from slack_sdk.errors import SlackApiError
        
        config = load_config()
        bot_token = config['slack_settings']['bot_token']
        configured_channel = config['slack_settings']['channel_id']
        
        client = WebClient(token=bot_token)
        
        debug_info = {
            'configured_channel': configured_channel,
            'bot_info': None,
            'channels': [],
            'conversations': [],
            'test_message_result': None
        }
        
        # Get bot info
        try:
            auth_result = client.auth_test()
            debug_info['bot_info'] = auth_result.data
        except Exception as e:
            debug_info['bot_info'] = f"Error: {str(e)}"
        
        # List channels the bot is in
        try:
            channels_result = client.conversations_list(types="public_channel,private_channel,im,mpim")
            debug_info['conversations'] = [
                {
                    'id': ch['id'],
                    'name': ch.get('name', 'N/A'),
                    'is_channel': ch.get('is_channel', False),
                    'is_private': ch.get('is_private', False),
                    'is_im': ch.get('is_im', False),
                    'is_member': ch.get('is_member', False)
                }
                for ch in channels_result['channels']
            ]
        except Exception as e:
            debug_info['conversations'] = f"Error: {str(e)}"
        
        # Test message to configured channel
        try:
            test_result = client.chat_postMessage(
                channel=configured_channel,
                text="🧪 StreamSnap bot test message - checking channel access"
            )
            debug_info['test_message_result'] = "Success - message posted"
        except SlackApiError as e:
            debug_info['test_message_result'] = f"Error: {e.response['error']}"
        except Exception as e:
            debug_info['test_message_result'] = f"Error: {str(e)}"
        
        return jsonify(debug_info)
        
    except Exception as e:
        print(f"❌ Debug channels endpoint error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/')
def index():
    """Main StreamSnap page."""
    version_info = load_version_info()
    return render_template('index.html', version_info=version_info)

@app.route('/api/version')
def api_version():
    """API endpoint for version information."""
    return jsonify(load_version_info())

def extract_video_id(url):
    """Extract video ID from YouTube URL."""
    import re
    
    # Handle different YouTube URL formats and extract video ID
    youtube_patterns = [
        r'(?:https?://)?(?:www\.)?youtube\.com/watch\?v=([a-zA-Z0-9_-]+)',
        r'(?:https?://)?(?:www\.)?youtu\.be/([a-zA-Z0-9_-]+)',
        r'(?:https?://)?(?:www\.)?youtube\.com/embed/([a-zA-Z0-9_-]+)',
        r'(?:https?://)?(?:www\.)?m\.youtube\.com/watch\?v=([a-zA-Z0-9_-]+)'
    ]
    
    for pattern in youtube_patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    
    return None

def clean_youtube_url(url):
    """Clean YouTube URL to remove playlist and other unnecessary parameters."""
    import re
    
    # Remove any leading/trailing whitespace
    url = url.strip()
    
    video_id = extract_video_id(url)
    
    if video_id:
        # Return clean YouTube URL with just the video ID
        clean_url = f"https://www.youtube.com/watch?v={video_id}"
        print(f"Cleaned URL: {url} -> {clean_url}")
        return clean_url
    
    # If it's not a recognized YouTube URL, return as-is
    print(f"URL not recognized as YouTube format, keeping as-is: {url}")
    return url

def format_transcript(transcript):
    """Format transcript with better structure and readability."""
    if not transcript:
        return transcript
    
    # Remove repetitive captions (common in YouTube auto-generated captions)
    lines = transcript.split('\n')
    formatted_lines = []
    prev_line = ""
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Skip "Kind: captions Language: en" header
        if line.startswith('Kind:') or line.startswith('Language:'):
            continue
            
        # Remove excessive repetition (YouTube often repeats the same text)
        if line != prev_line:
            # Break very long lines into sentences
            if len(line) > 200:
                # Split on sentence boundaries
                import re
                sentences = re.split(r'(?<=[.!?])\s+', line)
                for sentence in sentences:
                    if sentence.strip():
                        formatted_lines.append(sentence.strip())
            else:
                formatted_lines.append(line)
            prev_line = line
    
    # Group lines into paragraphs (every 4-6 lines)
    paragraphs = []
    current_paragraph = []
    
    for i, line in enumerate(formatted_lines):
        current_paragraph.append(line)
        
        # Create paragraph breaks based on content length or every 5-7 lines
        if (len(current_paragraph) >= 5 and len(' '.join(current_paragraph)) > 200) or len(current_paragraph) >= 7:
            paragraphs.append(' '.join(current_paragraph))
            current_paragraph = []
    
    # Add any remaining lines
    if current_paragraph:
        paragraphs.append(' '.join(current_paragraph))
    
    # Join paragraphs with double line breaks
    return '\n\n'.join(paragraphs)

def load_config():
    """Load configuration from YAML file or create default."""
    config_path = Path('config/config.yaml')
    
    # Default configuration
    default_config = {
        'ai_settings': {
            'azure_openai_endpoint': os.getenv('AZURE_OPENAI_ENDPOINT', ''),
            'azure_openai_api_key': os.getenv('AZURE_OPENAI_API_KEY', ''),
            'azure_openai_model': os.getenv('AZURE_OPENAI_MODEL', 'gpt-4'),
            'azure_openai_api_version': os.getenv('AZURE_OPENAI_API_VERSION', '2024-02-01'),
            'summary_length': int(os.getenv('SUMMARY_LENGTH', '250')),
            'timestamp_threshold': float(os.getenv('TIMESTAMP_THRESHOLD', '30.0')),
        },
        'processing_settings': {
            'max_video_duration': int(os.getenv('MAX_VIDEO_DURATION', '10800')),
            'prefer_transcript': os.getenv('PREFER_TRANSCRIPT', 'true').lower() == 'true',
            'enable_whisper_transcription': os.getenv('ENABLE_WHISPER', 'true').lower() == 'true',
            'chunk_size': int(os.getenv('CHUNK_SIZE', '1000')),
        },
        'slack_settings': {
            'bot_token': os.getenv('SLACK_BOT_TOKEN', ''),
            'signing_secret': os.getenv('SLACK_SIGNING_SECRET', ''),
            'channel_id': os.getenv('SLACK_CHANNEL_ID', ''),
            'auto_process_urls': os.getenv('SLACK_AUTO_PROCESS', 'false').lower() == 'true',
            'auto_detect_channels': os.getenv('SLACK_AUTO_DETECT', 'true').lower() == 'true',
            'discovered_channels': {},
            'recent_activity': [],
        },
        'ui_settings': {
            'app_name': os.getenv('APP_NAME', 'StreamSnap'),
            'brand_color': os.getenv('BRAND_COLOR', '#116df8'),
            'accent_color': os.getenv('ACCENT_COLOR', '#ff5100'),
        }
    }
    
    try:
        if config_path.exists():
            with open(config_path, 'r') as f:
                file_config = yaml.safe_load(f) or {}
            # Merge with defaults, but environment variables take precedence
            return deep_merge(default_config, file_config)
    except Exception as e:
        print(f"Error loading config: {e}")
    
    return default_config

def deep_merge(dict1, dict2):
    """Deep merge two dictionaries, preserving non-empty values from dict1 (env vars)."""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            # Only override if the existing value is empty and the new value is non-empty
            if key not in result or not result[key]:
                result[key] = value
    return result

def save_config(config):
    """Save configuration to YAML file."""
    config_path = Path('config/config.yaml')
    config_path.parent.mkdir(exist_ok=True)
    
    try:
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, indent=2)
        return True
    except Exception as e:
        print(f"Error saving config: {e}")
        return False

@app.route('/admin')
def admin():
    """Admin configuration page."""
    config = load_config()
    version_info = load_version_info()
    return render_template('admin.html', config=config, version_info=version_info)

@app.route('/admin/save', methods=['POST'])
def admin_save():
    """Save admin configuration."""
    try:
        config = load_config()
        
        # Update config from form data
        for section in ['ai_settings', 'processing_settings', 'slack_settings', 'ui_settings']:
            if section not in config:
                config[section] = {}
            
            for key, value in request.form.items():
                if key.startswith(f'{section}_'):
                    setting_name = key[len(f'{section}_'):]
                    
                    # Convert types appropriately
                    if setting_name in ['summary_length', 'max_video_duration', 'chunk_size']:
                        config[section][setting_name] = int(value) if value else 0
                    elif setting_name in ['timestamp_threshold']:
                        config[section][setting_name] = float(value) if value else 0.0
                    elif setting_name in ['prefer_transcript', 'auto_process_urls', 'enable_whisper_transcription']:
                        config[section][setting_name] = value.lower() == 'true'
                    else:
                        config[section][setting_name] = value
        
        if save_config(config):
            flash('Configuration saved successfully!', 'success')
        else:
            flash('Error saving configuration.', 'error')
            
    except Exception as e:
        flash(f'Error updating configuration: {str(e)}', 'error')
    
    return redirect(url_for('admin'))

@app.route('/dashboard')
def dashboard():
    """Slack activity dashboard."""
    # Seed activity from logs on first access if no activity exists
    config = load_config()
    if not config.get('slack_settings', {}).get('recent_activity'):
        seed_activity_from_logs()
    
    activity_data = get_slack_activity_data()
    version_info = load_version_info()
    return render_template('dashboard.html', activity=activity_data, version_info=version_info)

@app.route('/api/slack/activity')
def api_slack_activity():
    """API endpoint for Slack activity data (for AJAX updates)."""
    activity_data = get_slack_activity_data()
    return jsonify(activity_data)

@app.route('/api/system/status')
def api_system_status():
    """API endpoint for system status including active processing."""
    status = get_active_processing_status()
    return jsonify(status)

@app.route('/api/system/safe-restart', methods=['POST'])
def api_request_safe_restart():
    """API endpoint to request graceful shutdown and safe restart."""
    try:
        status = request_graceful_shutdown()
        return jsonify({
            'success': True,
            'message': 'Graceful shutdown requested',
            'status': status
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/system/cancel-restart', methods=['POST'])
def api_cancel_restart():
    """API endpoint to cancel graceful shutdown request."""
    global shutdown_requested
    try:
        shutdown_requested = False
        print("✅ Graceful shutdown cancelled - resuming normal operation")
        return jsonify({
            'success': True,
            'message': 'Graceful shutdown cancelled',
            'status': get_active_processing_status()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def get_working_proxy():
    """Test and return a working proxy from available free options."""
    import requests
    import time
    
    # List of free public proxies (residential IPs preferred)
    free_proxies = [
        # ProxyMesh free endpoints (often overloaded but worth trying)
        'http://us-ca.proxymesh.com:31280',
        'http://us-ny.proxymesh.com:31280',
        'http://us-fl.proxymesh.com:31280',
        'http://au.proxymesh.com:31280',
        'http://uk.proxymesh.com:31280',
        # Free proxy services (update these periodically)
        'http://proxy-daily.com:8080',
        'http://free-proxy.cz:8080',
        # Public HTTP proxies (residential-like IPs)
        'http://47.88.88.93:8080',
        'http://158.69.52.218:9300',
        'http://194.67.91.153:80',
        'http://103.149.162.194:80',
        # SOCKS5 proxies
        'socks5://198.49.68.80:80',
        'socks5://47.243.242.70:20000',
        'socks5://72.221.164.34:60671',
    ]
    
    # Check if manual proxy is set
    manual_proxy = os.getenv('YOUTUBE_PROXY_URL')
    if manual_proxy:
        print(f"🔧 Using manual proxy: {manual_proxy}")
        return manual_proxy
    
    # Skip proxy testing if disabled
    if os.getenv('YOUTUBE_DISABLE_PROXY', '').lower() == 'true':
        print("🚫 Proxy disabled via YOUTUBE_DISABLE_PROXY")
        return None
    
    # Test each proxy quickly
    for proxy_url in free_proxies:
        try:
            print(f"🧪 Testing proxy: {proxy_url}")
            proxies = {'http': proxy_url, 'https': proxy_url}
            
            # Quick test with httpbin (5 second timeout)
            response = requests.get('http://httpbin.org/ip', 
                                  proxies=proxies, 
                                  timeout=5)
            
            if response.status_code == 200:
                proxy_ip = response.json().get('origin', 'unknown')
                print(f"✅ Proxy working! IP: {proxy_ip}")
                return proxy_url
                
        except Exception as e:
            print(f"❌ Proxy failed: {str(e)}")
            continue
    
    print("⚠️ No working proxies found, proceeding without proxy")
    return None

def get_video_info_youtube_api(video_id):
    """Fallback: Get video info using YouTube Data API v3 when yt-dlp fails."""
    import requests
    
    api_key = os.getenv('YOUTUBE_API_KEY')
    if not api_key:
        raise Exception("YouTube API key not configured. Set YOUTUBE_API_KEY environment variable.")
    
    try:
        # Get video details
        url = f"https://www.googleapis.com/youtube/v3/videos"
        params = {
            'part': 'snippet,contentDetails,statistics',
            'id': video_id,
            'key': api_key
        }
        
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if not data.get('items'):
            raise Exception("Video not found or private")
            
        video = data['items'][0]
        snippet = video['snippet']
        details = video['contentDetails']
        stats = video['statistics']
        
        # Parse duration (PT4M13S format)
        duration_str = details.get('duration', 'PT0S')
        duration = parse_youtube_duration(duration_str)
        
        return {
            'title': snippet.get('title', 'Unknown Title'),
            'duration': duration,
            'thumbnail': snippet.get('thumbnails', {}).get('maxres', {}).get('url') or 
                        snippet.get('thumbnails', {}).get('high', {}).get('url'),
            'view_count': int(stats.get('viewCount', 0)),
            'upload_date': snippet.get('publishedAt', '').replace('-', '').replace('T', '').split('.')[0] + '00',
            'description': snippet.get('description', ''),
            'subtitles': {},  # API doesn't provide subtitles directly
            'automatic_captions': {},
            'chapters': []  # API doesn't provide chapters directly
        }
    except Exception as e:
        raise Exception(f"YouTube API error: {str(e)}")

def parse_youtube_duration(duration_str):
    """Parse YouTube API duration format (PT4M13S) to seconds."""
    import re
    
    pattern = r'PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?'
    match = re.match(pattern, duration_str)
    
    if not match:
        return 0
        
    hours = int(match.group(1) or 0)
    minutes = int(match.group(2) or 0)
    seconds = int(match.group(3) or 0)
    
    return hours * 3600 + minutes * 60 + seconds

def get_video_info(url):
    """Extract video information using yt-dlp with YouTube API fallback."""
    # Extract video ID for potential API fallback
    video_id = None
    if 'youtube.com/watch?v=' in url or 'youtu.be/' in url:
        import re
        patterns = [
            r'(?:youtube\.com/watch\?v=|youtu\.be/)([a-zA-Z0-9_-]{11})',
            r'youtube\.com/embed/([a-zA-Z0-9_-]{11})',
        ]
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                video_id = match.group(1)
                break
    
    try:
        ydl_opts = {
            'quiet': True,
            'no_warnings': True,
            'extract_flat': False,
            'socket_timeout': 60,
            'retries': 3,
            # Enhanced anti-bot detection measures
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'sleep_interval': 2,
            'max_sleep_interval': 8,
            'sleep_interval_subtitles': 2,
            # Reduce request frequency
            'ratelimit': 50000,  # 50KB/s limit (more conservative)
            # Additional headers to appear more human
            'http_headers': {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            },
            # Try to extract cookies from browser if available
            'cookiesfrombrowser': ('chrome',) if os.path.exists('/usr/bin/google-chrome') else None,
        }
        
        # Add proxy support with fallback
        proxy_url = get_working_proxy()
        if proxy_url:
            ydl_opts['proxy'] = proxy_url
            print(f"🔗 Using proxy: {proxy_url}")
            
        # Add custom cookies if provided
        cookies_file = os.getenv('YOUTUBE_COOKIES_FILE')
        if cookies_file and os.path.exists(cookies_file):
            ydl_opts['cookiefile'] = cookies_file
            print(f"🍪 Using cookies: {cookies_file}")
            
        # Add source IP if configured
        source_ip = os.getenv('YOUTUBE_SOURCE_IP')
        if source_ip:
            ydl_opts['source_address'] = source_ip
            print(f"📡 Using source IP: {source_ip}")
        
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            print("  🔍 Extracting video metadata...")
            info = ydl.extract_info(url, download=False)
            
            # Extract chapters if available
            chapters = info.get('chapters', [])
            if chapters is None:
                chapters = []
            chapter_count = len(chapters)
            print(f"  📑 Found {chapter_count} chapters" + (f": {[c.get('title', 'Untitled') for c in chapters[:3]]}{'...' if chapter_count > 3 else ''}" if chapter_count > 0 else ""))
            
            return {
                'title': info.get('title', 'Unknown Title'),
                'duration': info.get('duration', 0),
                'thumbnail': info.get('thumbnail'),
                'view_count': info.get('view_count', 0),
                'upload_date': info.get('upload_date'),
                'description': info.get('description', ''),
                'subtitles': info.get('subtitles', {}),
                'automatic_captions': info.get('automatic_captions', {}),
                'chapters': chapters
            }
    except Exception as e:
        error_msg = str(e)
        if "Private video" in error_msg:
            raise Exception("This video is private or restricted. Please use a public YouTube video.")
        elif "Video unavailable" in error_msg:
            raise Exception("This video is unavailable or has been removed.")
        elif "Sign in" in error_msg:
            raise Exception("This video requires authentication. Please use a public YouTube video.")
        elif "timeout" in error_msg.lower():
            raise Exception("Timeout while accessing video. Please try again.")
        elif "network" in error_msg.lower() or "connection" in error_msg.lower():
            raise Exception("Network error while accessing video. Please check your connection and try again.")
        else:
            raise Exception(f"Cannot access video: {error_msg}")

def get_transcript(video_info):
    """Extract transcript from video info."""
    transcript_text = ""
    
    # Try to get manual subtitles first (more accurate)
    subtitles = video_info.get('subtitles', {})
    auto_captions = video_info.get('automatic_captions', {})
    
    # Look for English subtitles with comprehensive language codes
    english_codes = ['en', 'en-US', 'en-GB', 'en-CA', 'en-AU', 'en-NZ', 'en-IE', 'en-ZA', 'en-IN']
    
    # First try exact English codes in manual subtitles
    for lang_code in english_codes:
        if lang_code in subtitles:
            print(f"Found manual subtitles in: {lang_code}")
            return extract_subtitle_text(subtitles[lang_code])
    
    # Then try exact English codes in auto-generated captions
    for lang_code in english_codes:
        if lang_code in auto_captions:
            print(f"Found auto-generated captions in: {lang_code}")
            return extract_subtitle_text(auto_captions[lang_code])
    
    # Try any language code that starts with 'en' (handles complex codes like en-nP7-2PuUl7o)
    print(f"Available subtitle languages: {list(subtitles.keys())}")
    print(f"Available auto-caption languages: {list(auto_captions.keys())}")
    
    for lang_code in list(subtitles.keys()) + list(auto_captions.keys()):
        if lang_code.startswith('en'):
            print(f"Found English-variant subtitles in: {lang_code}")
            source = subtitles if lang_code in subtitles else auto_captions
            transcript = extract_subtitle_text(source[lang_code])
            if transcript:
                return transcript
    
    # If no English, try any available language
    if subtitles:
        first_lang = next(iter(subtitles))
        return extract_subtitle_text(subtitles[first_lang])
    elif auto_captions:
        first_lang = next(iter(auto_captions))
        return extract_subtitle_text(auto_captions[first_lang])
    
    return None

def extract_subtitle_text(subtitle_list):
    """Extract text from subtitle format list with improved error handling."""
    print(f"Subtitle list contains {len(subtitle_list)} entries")
    
    # Find VTT format (preferred) or first available
    subtitle_url = None
    for i, sub in enumerate(subtitle_list):
        print(f"Entry {i}: ext={sub.get('ext')}, url exists={bool(sub.get('url'))}")
        if sub.get('ext') == 'vtt':
            subtitle_url = sub.get('url')
            break
    
    if not subtitle_url and subtitle_list:
        subtitle_url = subtitle_list[0].get('url')
        print(f"Using first available URL: {bool(subtitle_url)}")
    
    if not subtitle_url:
        print("No subtitle URL found")
        return None
    
    # Retry configuration for subtitle download
    max_retries = 2
    base_delay = 2.0
    
    for attempt in range(max_retries + 1):
        try:
            import requests
            import time
            import random
            
            if attempt > 0:
                delay = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 1)
                print(f"Retrying subtitle download in {delay:.2f} seconds (attempt {attempt + 1}/{max_retries + 1})")
                time.sleep(delay)
            
            print(f"Fetching subtitle from URL: {subtitle_url[:100]}... (attempt {attempt + 1}/{max_retries + 1})")
            response = requests.get(subtitle_url, timeout=45)  # Increased timeout
            print(f"Response status: {response.status_code}")
            response.raise_for_status()
            
            # Parse VTT content
            content = response.text
            print(f"Downloaded {len(content)} characters of subtitle data")
            lines = content.split('\n')
            transcript_lines = []
            
            # Parse VTT with timing information for better timestamp accuracy
            current_timestamp = None
            timed_segments = []
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('WEBVTT'):
                    continue
                    
                # Check if this is a timing line (e.g., "00:01:30.000 --> 00:01:35.000")
                if '-->' in line:
                    # Extract start time for this segment
                    start_time = line.split(' --> ')[0].strip()
                    current_timestamp = start_time
                    continue
                
                # Skip numeric sequence lines
                if line.isdigit():
                    continue
                
                # This is content - clean and store with timestamp
                if current_timestamp:
                    clean_line = re.sub(r'<[^>]+>', '', line)
                    if clean_line.strip():
                        timed_segments.append(f"[{current_timestamp}] {clean_line}")
            
            # Join timed segments for AI analysis
            result = ' '.join(timed_segments) if timed_segments else ' '.join([
                re.sub(r'<[^>]+>', '', line.strip()) for line in lines 
                if line.strip() and not line.startswith('WEBVTT') and not '-->' in line and not line.isdigit()
            ])
            print(f"Extracted transcript: {len(result)} characters, preview: {result[:100]}...")
            if attempt > 0:
                print(f"Subtitle download succeeded on attempt {attempt + 1}")
            return result if result.strip() else None
            
        except requests.exceptions.ConnectionError as e:
            print(f"Connection error on subtitle download attempt {attempt + 1}: {str(e)}")
            if attempt == max_retries:
                print(f"Failed to download subtitles after {max_retries + 1} attempts")
                return None
        except requests.exceptions.Timeout as e:
            print(f"Timeout error on subtitle download attempt {attempt + 1}: {str(e)}")
            if attempt == max_retries:
                print(f"Subtitle download timed out after {max_retries + 1} attempts")
                return None
        except Exception as e:
            print(f"Error extracting subtitle text on attempt {attempt + 1}: {e}")
            if attempt == max_retries:
                return None
    
    return None

def call_azure_openai(messages, config):
    """Call Azure OpenAI API with retry mechanism and exponential backoff."""
    import requests
    import json
    import time
    import random
    
    endpoint = config['ai_settings']['azure_openai_endpoint'].rstrip('/')
    api_key = config['ai_settings']['azure_openai_api_key']
    api_version = config['ai_settings']['azure_openai_api_version']
    model = config['ai_settings']['azure_openai_model']
    
    # Use direct HTTP API call instead of the OpenAI client
    url = f"{endpoint}/openai/deployments/{model}/chat/completions?api-version={api_version}"
    
    headers = {
        'Content-Type': 'application/json',
        'api-key': api_key
    }
    
    data = {
        'messages': messages,
        'temperature': 0.7,
        'max_tokens': 2000
    }
    
    # Retry configuration
    max_retries = 3
    base_delay = 1.0
    max_delay = 30.0
    
    for attempt in range(max_retries + 1):
        try:
            if attempt > 0:
                # Exponential backoff with jitter
                delay = min(base_delay * (2 ** (attempt - 1)) + random.uniform(0, 1), max_delay)
                print(f"Retrying Azure OpenAI API call in {delay:.2f} seconds (attempt {attempt + 1}/{max_retries + 1})")
                time.sleep(delay)
            
            print(f"Making Azure OpenAI API call to: {url} (attempt {attempt + 1}/{max_retries + 1})")
            response = requests.post(url, headers=headers, json=data, timeout=60)
            response.raise_for_status()
            
            result = response.json()
            if attempt > 0:
                print(f"Azure OpenAI API call succeeded on attempt {attempt + 1}")
            return result['choices'][0]['message']['content']
            
        except requests.exceptions.ConnectionError as e:
            print(f"Connection error on attempt {attempt + 1}: {str(e)}")
            if attempt == max_retries:
                raise Exception(f"Azure OpenAI API connection failed after {max_retries + 1} attempts: {str(e)}")
        except requests.exceptions.Timeout as e:
            print(f"Timeout error on attempt {attempt + 1}: {str(e)}")
            if attempt == max_retries:
                raise Exception(f"Azure OpenAI API timeout after {max_retries + 1} attempts: {str(e)}")
        except requests.exceptions.HTTPError as e:
            print(f"HTTP error on attempt {attempt + 1}: {str(e)}")
            # Don't retry on 4xx errors (client errors)
            if response.status_code < 500:
                raise Exception(f"Azure OpenAI API error: {str(e)}")
            if attempt == max_retries:
                raise Exception(f"Azure OpenAI API server error after {max_retries + 1} attempts: {str(e)}")
        except Exception as e:
            print(f"Unexpected error on attempt {attempt + 1}: {str(e)}")
            if attempt == max_retries:
                raise Exception(f"Azure OpenAI API error after {max_retries + 1} attempts: {str(e)}")

def transcribe_audio_with_whisper(video_url, config):
    """Download audio and transcribe using Azure OpenAI Whisper."""
    try:
        print("Starting audio transcription with Whisper...")
        
        # Try direct HTTP approach to avoid OpenAI library issues
        import requests
        
        # First test if we can reach the API endpoint
        endpoint = config['ai_settings']['azure_openai_endpoint'].rstrip('/')  # Remove trailing slash
        api_key = config['ai_settings']['azure_openai_api_key']
        api_version = config['ai_settings']['azure_openai_api_version']
        
        print(f"Testing Azure OpenAI connection to: {endpoint}")
        print("Step 1: Preparing connection test...")
        # Test the Whisper endpoint directly instead of generic deployments list  
        # Whisper uses a different API version than GPT models
        whisper_api_version = "2024-06-01"
        test_url = f"{endpoint}/openai/deployments/whisper/audio/transcriptions?api-version={whisper_api_version}"
        test_headers = {
            'api-key': api_key
        }
        
        print("Step 2: Making connection test request...")
        print(f"Testing URL: {test_url}")
        try:
            # Make a simple HEAD request to test if the endpoint exists
            test_response = requests.head(test_url, headers=test_headers, timeout=10)
            print(f"Connection test response: {test_response.status_code}")
            # 405 (Method Not Allowed) or 400 (Bad Request) is OK - means endpoint exists but needs proper data
            if test_response.status_code not in [200, 400, 405]:
                raise Exception(f"Azure OpenAI Whisper endpoint not accessible: {test_response.status_code}")
        except Exception as e:
            print(f"Connection test failed: {e}")
            print("Proceeding anyway - will attempt direct API call")
        
        print("Step 3: Connection test passed, importing httpx...")
        import httpx
        print("Step 4: Creating httpx client...")
        http_client = httpx.Client(timeout=120.0)
        print("Step 5: Skipping AzureOpenAI client due to library issues...")
        print("Using direct API approach instead")
        client = None
        
        # Download audio with yt-dlp
        with tempfile.TemporaryDirectory() as temp_dir:
            audio_path = os.path.join(temp_dir, "audio")
            
            ydl_opts = {
                'format': 'bestaudio[ext=mp3]/bestaudio[ext=m4a]/bestaudio',
                'outtmpl': f'{audio_path}.%(ext)s',
                'quiet': False,  # Enable logging to debug
                'no_warnings': False,
                'postprocessors': [{
                    'key': 'FFmpegExtractAudio',
                    'preferredcodec': 'mp3',
                    'preferredquality': '192',
                }],
                'prefer_ffmpeg': True,
                'extractaudio': True,
                'audioformat': 'mp3',
            }
            
            print("Downloading audio...")
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                ydl.download([video_url])
            
            # List all files to debug what was actually downloaded
            all_files = os.listdir(temp_dir)
            print(f"All files in temp directory: {all_files}")
            
            # Find the actual audio file (yt-dlp might change the extension)
            audio_files = [f for f in all_files if f.startswith('audio')]
            if not audio_files:
                raise Exception("No audio file was downloaded")
            
            actual_audio_path = os.path.join(temp_dir, audio_files[0])
            print(f"Downloaded audio file: {audio_files[0]}")
            
            # Check file size (Whisper has limits)
            file_size = os.path.getsize(actual_audio_path)
            print(f"Audio file size: {file_size / (1024*1024):.2f} MB")
            print(f"Audio file path: {actual_audio_path}")
            
            # Try to get file type using file command
            import subprocess
            try:
                file_type = subprocess.check_output(['file', actual_audio_path], text=True).strip()
                print(f"File type detection: {file_type}")
            except Exception as e:
                print(f"Could not detect file type: {e}")
            
            if file_size > 25 * 1024 * 1024:  # 25MB limit for Whisper
                raise Exception("Audio file too large for Whisper (>25MB). Try a shorter video.")
            
            # Transcribe with Whisper
            print("Transcribing audio with Whisper...")
            
            if client is not None:
                # Use OpenAI client if available
                with open(actual_audio_path, 'rb') as audio_file:
                    transcript_response = client.audio.transcriptions.create(
                        model="whisper",
                        file=audio_file,
                        response_format="text"
                    )
                transcript_text = transcript_response.strip()
            else:
                # Use direct API calls if OpenAI client failed
                print("Making direct API call to Whisper...")
                whisper_url = f"{endpoint}/openai/deployments/whisper/audio/transcriptions?api-version={whisper_api_version}"
                
                with open(actual_audio_path, 'rb') as audio_file:
                    # Use MP3 format - universally supported
                    files = {'file': ('audio.mp3', audio_file, 'audio/mpeg')}
                    data = {
                        'model': 'whisper',
                        'response_format': 'text'
                    }
                    headers = {'api-key': api_key}
                    
                    print(f"Making request to: {whisper_url}")
                    print(f"Request headers: {headers}")
                    print(f"Request data: {data}")
                    
                    # Increased timeout for Whisper API calls (audio processing takes time)
                    response = requests.post(whisper_url, headers=headers, files=files, data=data, timeout=180)
                    print(f"Response status: {response.status_code}")
                    print(f"Response headers: {dict(response.headers)}")
                    print(f"Response content: {response.text[:500]}...")
                    
                    if response.status_code != 200:
                        print(f"API Error {response.status_code}: {response.text}")
                        raise Exception(f"Whisper API error {response.status_code}: {response.text}")
                    
                    transcript_text = response.text.strip()
            
            print(f"Whisper transcription complete: {len(transcript_text)} characters")
            return transcript_text if transcript_text else None
            
    except Exception as e:
        print(f"Whisper transcription failed: {str(e)}")
        return None

def transcribe_audio_with_whisper_timestamps(video_url, config):
    """Download audio and transcribe using Azure OpenAI Whisper with timestamps."""
    try:
        print("🔥 FUNCTION CALLED: transcribe_audio_with_whisper_timestamps")
        print("Starting audio transcription with Whisper (with timestamps)...")
        
        # Try direct HTTP approach to avoid OpenAI library issues
        import requests
        
        # Get API configuration
        endpoint = config['ai_settings']['azure_openai_endpoint'].rstrip('/')
        api_key = config['ai_settings']['azure_openai_api_key']
        whisper_api_version = "2024-06-01"
        
        # Download audio with yt-dlp
        with tempfile.TemporaryDirectory() as temp_dir:
            audio_path = os.path.join(temp_dir, "audio")
            
            ydl_opts = {
                'format': 'bestaudio[ext=mp3]/bestaudio[ext=m4a]/bestaudio',
                'outtmpl': f'{audio_path}.%(ext)s',
                'quiet': True,
                'no_warnings': True,
                'postprocessors': [{
                    'key': 'FFmpegExtractAudio',
                    'preferredcodec': 'mp3',
                    'preferredquality': '192',
                }],
                'prefer_ffmpeg': True,
                'extractaudio': True,
                'audioformat': 'mp3',
            }
            
            print("🎵 Downloading audio for Whisper transcription...")
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                ydl.download([video_url])
            
            # Find the actual audio file
            all_files = os.listdir(temp_dir)
            audio_files = [f for f in all_files if f.startswith('audio')]
            if not audio_files:
                raise Exception("No audio file was downloaded")
            
            actual_audio_path = os.path.join(temp_dir, audio_files[0])
            
            # Check file size (Whisper has 25MB limit)
            file_size = os.path.getsize(actual_audio_path)
            print(f"🎵 Audio file size: {file_size / (1024*1024):.2f} MB")
            
            if file_size > 25 * 1024 * 1024:  # 25MB limit for Whisper
                raise Exception("Audio file too large for Whisper (>25MB). Try a shorter video.")
            
            # Transcribe with Whisper using verbose_json format for timestamps
            print("🎙️ Transcribing audio with Whisper (timestamps enabled)...")
            whisper_url = f"{endpoint}/openai/deployments/whisper/audio/transcriptions?api-version={whisper_api_version}"
            
            with open(actual_audio_path, 'rb') as audio_file:
                files = {'file': ('audio.mp3', audio_file, 'audio/mpeg')}
                data = {
                    'model': 'whisper',
                    'response_format': 'verbose_json',  # Required for segment timestamps
                    'timestamp_granularities[]': 'segment'  # Get segment-level timestamps
                }
                headers = {'api-key': api_key}
                
                print(f"🔍 TIMESTAMP WHISPER: Making request to: {whisper_url}")
                print(f"🔍 TIMESTAMP WHISPER: Request data: {data}")
                
                # Increased timeout for Whisper API calls
                response = requests.post(whisper_url, headers=headers, files=files, data=data, timeout=180)
                
                if response.status_code != 200:
                    print(f"Whisper API Error {response.status_code}: {response.text}")
                    raise Exception(f"Whisper API error {response.status_code}: {response.text}")
                
                transcript_json = response.json()
            
            # Parse the response to extract segments with timestamps
            segments = transcript_json.get('segments', [])
            full_text = transcript_json.get('text', '')
            
            print(f"🎙️ Whisper transcription complete: {len(full_text)} characters, {len(segments)} segments")
            
            return {
                'text': full_text,
                'segments': segments,
                'duration': transcript_json.get('duration', 0)
            }
            
    except Exception as e:
        print(f"Whisper timestamp transcription failed: {str(e)}")
        return None

def generate_timestamps_from_whisper(whisper_data, summary, video_id, config):
    """Generate accurate timestamps using correct logic: find natural boundaries, then summarize each segment."""
    if not whisper_data or not whisper_data.get('segments'):
        return None
    
    segments = whisper_data['segments']
    full_text = whisper_data['text']
    
    print(f"🎯 Analyzing {len(segments)} Whisper segments for natural topic boundaries...")
    
    # Step 1: Create timestamped transcript for AI analysis
    timestamped_transcript = ""
    for i, segment in enumerate(segments):
        start_time = segment.get('start', 0)
        text = segment.get('text', '').strip()
        start_formatted = f"{int(start_time//60):02d}:{int(start_time%60):02d}"
        timestamped_transcript += f"[{i:03d}] [{start_formatted}] {text}\n"
    
    # Step 2: AI identifies natural topic boundaries (no predetermined count)
    boundary_messages = [
        {
            "role": "system", 
            "content": """You are an expert at analyzing conversation transcripts to identify natural topic boundaries.

Your task:
1. Read through the entire timestamped transcript
2. Identify where the conversation naturally changes topics or focus
3. Return the segment numbers where these natural transitions occur
4. Don't force a specific number of topics - find as many or as few as naturally exist

Look for:
- Changes in subject matter
- New discussion points being introduced  
- Natural conversational shifts
- Transitions between different aspects of the topic

Return ONLY a JSON array of segment numbers where topic changes occur:
[0, 45, 120, 200, 275]

Return only the JSON array, no other text."""
        },
        {
            "role": "user",
            "content": f"""Find all natural topic boundaries in this conversation transcript.

VIDEO: {video_id}
TOTAL SEGMENTS: {len(segments)}

TIMESTAMPED TRANSCRIPT:
{timestamped_transcript[:10000]}

Return ONLY the JSON array of segment numbers where topics naturally change."""
        }
    ]
    
    try:
        print("🎯 Step 1: AI identifying natural topic boundaries...")
        boundaries_response = call_azure_openai(boundary_messages, config)
        
        # Parse boundary segment numbers
        import json
        boundary_segments = json.loads(boundaries_response.strip())
        print(f"🎯 Found {len(boundary_segments)} natural topic boundaries: {boundary_segments}")
        
        # Step 3: Create conversation segments between boundaries
        conversation_segments = []
        for i, start_seg in enumerate(boundary_segments):
            end_seg = boundary_segments[i + 1] if i + 1 < len(boundary_segments) else len(segments)
            
            # Get text for this conversation segment
            segment_text = ""
            start_time = segments[start_seg].get('start', 0)
            
            for seg_idx in range(start_seg, min(end_seg, len(segments))):
                segment_text += segments[seg_idx].get('text', '').strip() + " "
            
            conversation_segments.append({
                'start_segment': start_seg,
                'start_time': start_time,
                'text': segment_text.strip()
            })
        
        # Step 4: AI summarizes each conversation segment separately
        print(f"🎯 Step 2: AI summarizing {len(conversation_segments)} conversation segments...")
        segment_summaries = []
        
        for i, conv_seg in enumerate(conversation_segments):
            summary_messages = [
                {
                    "role": "system",
                    "content": """You are an expert at summarizing conversation segments. 

Your task:
1. Read the conversation segment text
2. Create a concise title (3-8 words)
3. Write a summary paragraph (2-4 sentences)

Format your response as:
TITLE: [title here]
SUMMARY: [summary here]

Do not refer to "this segment" or "this part" - write as if describing the content directly."""
                },
                {
                    "role": "user", 
                    "content": f"""Summarize this conversation segment:

SEGMENT TEXT:
{conv_seg['text'][:2000]}

Provide title and summary in the specified format."""
                }
            ]
            
            try:
                segment_response = call_azure_openai(summary_messages, config)
                
                # Parse title and summary
                lines = segment_response.strip().split('\n')
                title = ""
                summary_text = ""
                
                for line in lines:
                    if line.startswith('TITLE:'):
                        title = line.replace('TITLE:', '').strip()
                    elif line.startswith('SUMMARY:'):
                        summary_text = line.replace('SUMMARY:', '').strip()
                
                if title and summary_text:
                    start_time_formatted = f"{int(conv_seg['start_time']//60):02d}:{int(conv_seg['start_time']%60):02d}"
                    start_seconds = int(conv_seg['start_time'])
                    
                    segment_summaries.append({
                        'title': title,
                        'summary': summary_text,
                        'timestamp_link': f"**[{i+1}. {title}](https://youtube.com/watch?v={video_id}&t={start_seconds}s)**",
                        'timestamp_formatted': start_time_formatted,
                        'timestamp_seconds': start_seconds
                    })
                    
                    print(f"  🎯 Segment {i+1}: {title} at {start_time_formatted}")
                
            except Exception as e:
                print(f"⚠️ Failed to summarize segment {i+1}: {str(e)}")
        
        # Step 5: Generate final document structure
        if segment_summaries:
            # Create summary sections with YouTube links
            summary_sections = []
            timestamp_list = []
            
            for seg in segment_summaries:
                summary_sections.append(f"{seg['timestamp_link']}\n{seg['summary']}")
                timestamp_list.append(f"**[{seg['timestamp_formatted']}](https://youtube.com/watch?v={video_id}&t={seg['timestamp_seconds']}s) - {seg['title']}**")
            
            # Combine into final format
            final_content = "\n\n---\n\n".join(summary_sections)
            final_timestamps = "\n".join(timestamp_list)
            
            print(f"✅ Generated {len(segment_summaries)} conversation segments with precise timestamps")
            return {
                'summary_sections': final_content,
                'timestamp_list': final_timestamps
            }
        
        return None
        
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse AI response as JSON: {str(e)}")
        print(f"AI Response: {boundaries_response[:200]}...")
        return None
    except Exception as e:
        print(f"❌ Failed to generate timestamps from Whisper: {str(e)}")
        return None

def generate_summary_with_chapters(transcript, title, video_id, chapters, config):
    """Generate summary using accurate YouTube chapter timestamps."""
    if not chapters:
        return generate_summary(transcript, title, video_id, config)
    
    # Create chapter reference for AI
    chapter_info = "\n".join([
        f"{int(ch.get('start_time', 0))}s - {ch.get('title', 'Untitled')}"
        for ch in chapters
    ])
    
    messages = [
        {
            "role": "system", 
            "content": f"""You are an expert at creating comprehensive video summaries. You will receive a transcript and EXACT chapter timestamps from YouTube.

CRITICAL INSTRUCTIONS:
- Use the EXACT timestamps provided in the chapter information
- Create 3-5 key sections based on the most important chapters
- Include clickable timestamp links using the exact chapter start times
- Format: **[Section Title](https://youtube.com/watch?v={video_id}&t=XXXs)**
- Convert chapter start times to seconds for the URL parameter

CHAPTER TIMESTAMPS (USE THESE EXACTLY):
{chapter_info}

Create a well-structured summary with the most important topics, using the exact timestamps from the chapter data above."""
        },
        {
            "role": "user",
            "content": f"Create a summary for this video titled '{title}' using the chapter timestamps provided. Video ID: {video_id}\n\nTranscript:\n{transcript[:8000]}"
        }
    ]
    
    return call_azure_openai(messages, config)

def generate_summary(transcript, title, video_id, config):
    """Generate AI summary from transcript with YouTube timestamp references."""
    word_count = config['ai_settings']['summary_length']
    
    messages = [
        {
            "role": "system",
            "content": f"""You are an expert at creating concise, informative summaries of video content. Create a well-structured summary of approximately {word_count} words that captures the key points, insights, and takeaways.

FORMATTING REQUIREMENTS:
- Use proper paragraphs (separate with double line breaks)
- Include clickable YouTube timestamp references for key topics using format: [Topic Name](https://youtube.com/watch?v={video_id}&t=XXXs) where XXX is estimated seconds
- Include clickable reference links when mentioning:
  * Companies, products, or services (format: [Company Name](https://company.com))
  * People or speakers (format: [Person Name](https://linkedin.com/in/person) or relevant social media)
  * Technologies, tools, or platforms mentioned
  * Research studies, reports, or publications
- Structure with clear topic transitions
- Use bullet points or numbered lists for key takeaways when appropriate
- Make it engaging and scannable

YOUTUBE TIMESTAMP GUIDELINES:
- CRITICAL: Make ALL numbered section titles clickable with YouTube timestamp links
- Format numbered sections as: "### **[1. Topic Title](https://youtube.com/watch?v={video_id}&t=XXXs)**"
- Estimate approximate timestamps for each major section (e.g., 120s, 600s, 1200s, 1800s, 2400s)
- Space timestamps logically throughout the video duration based on section progression
- Every numbered section title MUST be a clickable YouTube timestamp link
- Examples: 
  * "### **[1. AI's Impact on Young Workers](https://youtube.com/watch?v={video_id}&t=120s)**"
  * "### **[2. The Politicization of AI](https://youtube.com/watch?v={video_id}&t=780s)**"
  * "### **[3. Google's Breakthrough Technology](https://youtube.com/watch?v={video_id}&t=1440s)**"
- Within section content, include additional reference links to companies, people, or external resources"""
        },
        {
            "role": "user",
            "content": f"Please create a comprehensive summary with clickable YouTube timestamp links and other relevant references for this video titled '{title}'. Include 3-5 strategic timestamp links to key discussion points within the summary text:\n\n{transcript}"
        }
    ]
    
    return call_azure_openai(messages, config)

def generate_timestamps_from_chapters(chapters, video_id):
    """Generate timestamps from YouTube chapters - most accurate method."""
    if not chapters:
        return None
    
    timestamps = []
    
    for chapter in chapters:
        start_time = int(chapter.get('start_time', 0))
        title = chapter.get('title', 'Untitled Chapter')
        
        # Convert seconds to MM:SS format
        mins = start_time // 60
        secs = start_time % 60
        time_str = f"{mins}:{secs:02d}"
        
        # Create clickable timestamp with proper formatting
        timestamp_link = f"**[{time_str}](https://youtube.com/watch?v={video_id}&t={start_time}s) - {title}**"
        timestamps.append(timestamp_link)
    
    return '\n\n'.join(timestamps)  # Double line break for better spacing

def generate_chapter_summaries(chapters, transcript, video_id, config):
    """Generate chapter-by-chapter summaries when both chapters and transcript are available."""
    if not chapters or not transcript:
        return None
    
    import re
    
    def convert_timestamp_to_seconds(timestamp_str):
        """Convert HH:MM:SS.mmm to seconds."""
        try:
            if '.' in timestamp_str:
                time_part, ms_part = timestamp_str.split('.')
            else:
                time_part, ms_part = timestamp_str, '0'
            
            parts = time_part.split(':')
            if len(parts) == 3:  # HH:MM:SS
                hours, minutes, seconds = map(int, parts)
                return hours * 3600 + minutes * 60 + seconds
            elif len(parts) == 2:  # MM:SS
                minutes, seconds = map(int, parts)
                return minutes * 60 + seconds
            else:  # SS
                return int(parts[0])
        except:
            return 0
    
    def extract_chapter_content(transcript, start_time, end_time):
        """Extract transcript content for a specific time range."""
        content_parts = []
        
        # Parse transcript segments with timing
        segments = re.findall(r'\[([^\]]+)\]\s*([^[]*)', transcript)
        
        for timestamp_str, content in segments:
            segment_time = convert_timestamp_to_seconds(timestamp_str)
            
            # Include content that falls within the chapter timeframe
            if start_time <= segment_time < end_time:
                if content.strip():
                    content_parts.append(content.strip())
        
        return ' '.join(content_parts)
    
    # Generate individual chapter summaries
    chapter_summaries = []
    timestamp_links = []
    
    for i, chapter in enumerate(chapters):
        start_time = int(chapter.get('start_time', 0))
        title = chapter.get('title', 'Untitled Chapter')
        
        # Determine end time (next chapter's start time or video end)
        if i + 1 < len(chapters):
            end_time = int(chapters[i + 1].get('start_time', start_time + 300))
        else:
            end_time = start_time + 9999  # Large number for last chapter
        
        # Extract content for this chapter
        chapter_content = extract_chapter_content(transcript, start_time, end_time)
        print(f"🔍 Chapter '{title}': extracted {len(chapter_content)} chars from {start_time}s to {end_time}s")
        
        if chapter_content:
            # Generate summary for this chapter
            chapter_summary_prompt = [
                {
                    "role": "system",
                    "content": f"""You are an expert at summarizing video content. Create a concise summary (2-3 sentences) for this chapter titled "{title}". 

REQUIREMENTS:
- Start directly with the content, don't mention "this chapter" or "this segment"
- Focus on key points and insights
- Be engaging and informative
- Include relevant details and context
- Use present tense"""
                },
                {
                    "role": "user", 
                    "content": f"Chapter: {title}\n\nContent:\n{chapter_content}"
                }
            ]
            
            try:
                response = call_azure_openai(chapter_summary_prompt, config)
                if response and isinstance(response, str):
                    chapter_summary = response.strip()
                else:
                    chapter_summary = f"Content covering {title.lower()}."
            except Exception as e:
                print(f"Error generating summary for chapter '{title}': {str(e)}")
                chapter_summary = f"Content covering {title.lower()}."
            
            # Format time for display
            mins = start_time // 60
            secs = start_time % 60
            time_str = f"{mins}:{secs:02d}"
            
            # Create chapter summary section
            chapter_link = f"https://youtube.com/watch?v={video_id}&t={start_time}s"
            chapter_section = f"### **[{title}]({chapter_link})**  \n{chapter_summary}"
            chapter_summaries.append(chapter_section)
            
            # Create timestamp link
            timestamp_link = f"**[{time_str}](https://youtube.com/watch?v={video_id}&t={start_time}s) - {title}**"
            timestamp_links.append(timestamp_link)
    
    if chapter_summaries:
        # Combine into final format
        summary_content = '\n\n---\n\n'.join(chapter_summaries)
        timestamp_content = '\n\n'.join(timestamp_links)
        
        return {
            'summary_sections': summary_content,
            'timestamp_list': timestamp_content
        }
    
    return None

def generate_timestamps(transcript, title, video_id, config):
    """Generate smart timestamps from transcript."""
    threshold = config['ai_settings']['timestamp_threshold']
    
    messages = [
        {
            "role": "system",
            "content": f"""You are an expert at analyzing video transcripts to create meaningful, clickable timestamps. You will receive a transcript with timing information in the format [HH:MM:SS.mmm] followed by the spoken content.

CRITICAL INSTRUCTIONS:
- The transcript contains ACTUAL TIMING DATA in [HH:MM:SS.mmm] format - USE THIS PRECISE TIMING
- Look for topic changes, new concepts, and meaningful segments based on content
- Extract the exact timestamps from the [HH:MM:SS.mmm] markers where topics change
- Do NOT create artificial intervals - use the real timing markers provided

TIMING DATA FORMAT:
- Transcript format: "[00:01:30.000] Speaker says something [00:01:35.000] Next segment"
- Use the exact HH:MM:SS timing from these markers
- Convert to MM:SS format for display (e.g., [00:01:30.000] → 1:30)
- Convert to total seconds for YouTube links (e.g., 1:30 → 90s)

FORMATTING REQUIREMENTS:
- Format: **[MM:SS](https://youtube.com/watch?v={video_id}&t=XXXs) - Topic Title**
- Extract MM:SS from the [HH:MM:SS.mmm] timing markers in the transcript
- Include descriptive titles that reflect the actual content discussed at that moment
- Aim for timestamps at least {threshold} seconds apart
- Use proper markdown formatting with bold timestamps
- Include clickable YouTube links with timestamp parameters (&t=XXXs where XXX is total seconds)

ANALYSIS PROCESS:
1. Scan through the timed transcript segments
2. Identify where speakers introduce new topics using the actual [HH:MM:SS.mmm] markers
3. Look for content transitions, new concepts, examples, or subject changes
4. Use the precise timing from the transcript data, not estimated times
5. Create meaningful topic titles based on what's actually being discussed

CONTENT-BASED STRUCTURE:
- Always start with **[0:00](https://youtube.com/watch?v={video_id}&t=0s) - Introduction**
- Add timestamps using the exact times from [HH:MM:SS.mmm] markers where content changes
- Use descriptive titles that reflect the specific content being discussed
- Extract the conclusion timestamp from the actual timing data"""
        },
        {
            "role": "user",
            "content": f"Create clickable, well-formatted timestamps for this video titled '{title}'. Use the video ID '{video_id}' in all YouTube timestamp links:\n\n{transcript}"
        }
    ]
    
    return call_azure_openai(messages, config)

def clean_canvas_markdown(content):
    """Clean markdown content to be compatible with Slack Canvas API."""
    lines = content.split('\n')
    cleaned_lines = []
    
    for line in lines:
        # Convert #### headings to ### (Canvas doesn't support level 4+)
        if line.startswith('#### '):
            line = line.replace('#### ', '### ')
        elif line.startswith('##### '):
            line = line.replace('##### ', '### ')
        elif line.startswith('###### '):
            line = line.replace('###### ', '### ')
            
        # Remove any emojis that might cause issues (keep basic ones)
        # Keep common ones like ✅ ❌ but remove complex Unicode
        
        cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines)

def format_duration(seconds):
    """Convert seconds to HH:MM:SS or MM:SS format."""
    if not seconds or not isinstance(seconds, (int, float)):
        return "Unknown"
    
    seconds = int(seconds)
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    
    if hours > 0:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    else:
        return f"{minutes}:{secs:02d}"

def create_slack_canvas_content(video_info, summary, timestamps, transcript):
    """Create Slack Canvas content using proper Canvas format."""
    video_title = video_info.get('title', 'Unknown Video')
    video_duration = video_info.get('duration', '')
    video_url = video_info.get('url', '')
    
    # Create Canvas content using only supported markdown features
    # Canvas API only supports heading levels 1-3 (# ## ###)
    # Note: Title is set via Canvas API title parameter, so no need for # title in content
    formatted_duration = format_duration(video_duration)
    content = f"""**Duration:** {formatted_duration}
**Video:** {video_url}
**Processed by:** StreamSnap AI

## 📝 Summary

{summary}

## ⏰ Timestamps

{timestamps}
"""
    
    # Clean the content to ensure Canvas compatibility
    cleaned_content = clean_canvas_markdown(content)
    return cleaned_content

def convert_summary_to_slack_format(summary):
    """Convert markdown summary to Slack-compatible mrkdwn format."""
    # Convert markdown headers to bold text
    slack_summary = summary.replace('### ', '*').replace('#### ', '*')
    
    # Convert markdown links [text](url) to Slack format <url|text>
    import re
    link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
    slack_summary = re.sub(link_pattern, r'<\2|\1>', slack_summary)
    
    # Convert **bold** to *bold* (Slack format)
    slack_summary = re.sub(r'\*\*([^*]+)\*\*', r'*\1*', slack_summary)
    
    # Limit length for Canvas (Slack has limits)
    if len(slack_summary) > 2900:
        slack_summary = slack_summary[:2900] + "...\n\n_Full summary available in StreamSnap._"
    
    return slack_summary

def convert_timestamps_to_slack_format(timestamps):
    """Convert markdown timestamps to Slack-compatible format."""
    # Convert markdown links to Slack format
    import re
    
    # Convert **[MM:SS](url) - Title** to *MM:SS* - <url|Title>
    timestamp_pattern = r'\*\*\[([^\]]+)\]\(([^)]+)\) - ([^*]+)\*\*'
    slack_timestamps = re.sub(timestamp_pattern, r'*\1* - <\2|\3>', timestamps)
    
    # Also handle simpler [MM:SS](url) - Title format
    simple_pattern = r'\[([^\]]+)\]\(([^)]+)\) - ([^\n]+)'
    slack_timestamps = re.sub(simple_pattern, r'*\1* - <\2|\3>', slack_timestamps)
    
    # Limit length for Canvas
    if len(slack_timestamps) > 2900:
        slack_timestamps = slack_timestamps[:2900] + "...\n\n_Full timestamps available in StreamSnap._"
    
    return slack_timestamps

def create_slack_canvas(canvas_content, config):
    """Create a Slack Canvas document using the official Slack SDK."""
    try:
        from slack_sdk import WebClient
        from slack_sdk.errors import SlackApiError
        
        bot_token = config['slack_settings']['bot_token']
        if not bot_token:
            print("No Slack bot token configured")
            return None
        
        client = WebClient(token=bot_token)
        
        # Extract title from the content (first line after #)
        lines = canvas_content.split('\n')
        title = "StreamSnap Video Summary"
        for line in lines:
            if line.startswith('# '):
                title = line[2:].strip()  # Remove "# " prefix
                break
        
        # Debug: Print canvas content before sending
        print(f"🔍 Canvas title: {title}")
        print(f"🔍 Canvas content length: {len(canvas_content)} chars")
        print("🔍 Canvas content preview:")
        for i, line in enumerate(canvas_content.split('\n')[:20], 1):
            print(f"   {i:2d}: {line}")
        
        # Create Canvas using Slack SDK - try channel canvas first
        channel_id = config['slack_settings']['channel_id'] 
        
        print("🔍 About to call conversations.canvases.create for channel canvas...")
        try:
            # Try to create a channel canvas (automatically shared with all channel members)
            result = client.conversations_canvases_create(
                channel_id=channel_id,
                title=title,
                document_content={
                    "type": "markdown", 
                    "markdown": canvas_content
                }
            )
            print("✅ Successfully created channel canvas (automatically shared with all members)")
        except Exception as channel_error:
            print(f"⚠️ Channel canvas creation failed: {channel_error}")
            # Fallback to standalone canvas
            print("🔄 Falling back to standalone canvas creation...")
            result = client.canvases_create(
                title=title,
                document_content={
                    "type": "markdown",
                    "markdown": canvas_content
                }
            )
            print("🔍 Canvas API call completed successfully")
        except Exception as api_error:
            print(f"🔍 Canvas API call failed with exception: {api_error}")
            print(f"🔍 Exception type: {type(api_error)}")
            raise
        
        # Debug: Print full API response
        print(f"🔍 Canvas API response: {result}")
        print(f"🔍 Response type: {type(result)}")
        if hasattr(result, 'data'):
            print(f"🔍 Response data: {result.data}")
        if hasattr(result, '__dict__'):
            print(f"🔍 Response attributes: {result.__dict__}")
        
        if result and result.get("ok"):
            # Canvas ID is directly in the response, not nested under "canvas"
            canvas_id = result.get("canvas_id")
            print(f"🔍 Canvas creation result: ok={result.get('ok')}, canvas_id={canvas_id}")
            if canvas_id:
                print(f"✅ Successfully created Slack Canvas: {canvas_id}")
                return canvas_id
            else:
                print("❌ Failed to create Slack Canvas: No canvas ID returned")
                print(f"🔍 Full response for debugging: {result}")
                return None
        else:
            error_msg = result.get('error', 'Unknown error') if result else 'No response from API'
            print(f"❌ Failed to create Slack Canvas: {error_msg}")
            print(f"🔍 Full response for debugging: {result}")
            return None
            
    except SlackApiError as e:
        error_code = e.response.get('error', 'unknown')
        error_details = e.response.get('response_metadata', {})
        print(f"Slack API error creating Canvas: {error_code}")
        print(f"Full error response: {e.response}")
        
        # If Canvas creation fails, we'll fall back to regular message
        if error_code in ['canvas_creation_failed', 'missing_scope', 'feature_not_enabled']:
            print("Canvas API not available, will fall back to regular message")
        return None
    except Exception as e:
        print(f"Error creating Slack Canvas: {str(e)}")
        return None

def post_simple_canvas_link(canvas_id, config):
    """Post a simple message with just the Canvas link."""
    try:
        from slack_sdk import WebClient
        
        bot_token = config['slack_settings']['bot_token']
        channel_id = config['slack_settings']['channel_id']
        
        if not bot_token or not channel_id:
            print("Missing Slack configuration for Canvas link")
            return False
        
        client = WebClient(token=bot_token)
        
        # Get workspace info to construct proper Canvas URL
        workspace_domain = 'vq8'  # Default fallback
        team_id = None
        
        try:
            # Get team ID from auth test
            auth_info = client.auth_test()
            team_id = auth_info.get('team_id')
            workspace_url = auth_info.get('url', '')
            
            if workspace_url:
                # Extract domain from URL like https://vq8.slack.com/
                import re
                match = re.search(r'https://([^.]+)\.slack\.com', workspace_url)
                if match:
                    workspace_domain = match.group(1)
            
        except Exception as e:
            print(f"⚠️ Error getting workspace info: {e}")
            team_id = 'T02L2C5BJ'  # Fallback team ID
        
        # Canvas URL format is https://WORKSPACE.slack.com/docs/TEAM_ID/CANVAS_ID
        if not team_id:
            team_id = 'T02L2C5BJ'  # Fallback team ID
            
        canvas_url = f"https://{workspace_domain}.slack.com/docs/{team_id}/{canvas_id}"
        print(f"🔍 Generated Canvas URL: {canvas_url}")
        
        result = client.chat_postMessage(
            channel=channel_id,
            text=canvas_url,
            unfurl_links=True,
            unfurl_media=True
        )
        
        if result.get("ok"):
            print(f"✅ Posted Canvas link to channel: {channel_id}")
            return True
        else:
            print(f"❌ Failed to post Canvas link: {result.get('error')}")
            return False
            
    except Exception as e:
        print(f"❌ Error posting Canvas link: {str(e)}")
        return False

def post_threaded_canvas_reply(canvas_id, config, channel_id, message_ts):
    """Post Canvas link as a threaded reply to the original YouTube message."""
    try:
        from slack_sdk import WebClient
        
        bot_token = config['slack_settings']['bot_token']
        
        if not bot_token or not channel_id or not message_ts:
            print("Missing required parameters for threaded Canvas reply")
            return False
        
        client = WebClient(token=bot_token)
        
        # Get workspace info to construct proper Canvas URL
        workspace_domain = 'vq8'  # Default fallback
        team_id = None
        
        try:
            # Get team ID from auth test
            auth_info = client.auth_test()
            team_id = auth_info.get('team_id')
            workspace_url = auth_info.get('url', '')
            
            if workspace_url:
                # Extract domain from URL like https://vq8.slack.com/
                import re
                match = re.search(r'https://([^.]+)\.slack\.com', workspace_url)
                if match:
                    workspace_domain = match.group(1)
        except Exception as e:
            print(f"⚠️ Error getting workspace info: {e}")
            team_id = 'T02L2C5BJ'  # Fallback team ID
        
        # Canvas URL format is https://WORKSPACE.slack.com/docs/TEAM_ID/CANVAS_ID
        if not team_id:
            team_id = 'T02L2C5BJ'  # Fallback team ID
            
        canvas_url = f"https://{workspace_domain}.slack.com/docs/{team_id}/{canvas_id}"
        print(f"🔍 Generated threaded Canvas URL: {canvas_url}")
        
        # Post as threaded reply to original message
        print(f"🔍 Attempting threaded reply with parameters:")
        print(f"   - channel: {channel_id}")
        print(f"   - thread_ts: {message_ts}")
        print(f"   - message_ts type: {type(message_ts)}")
        print(f"   - message_ts length: {len(str(message_ts))}")
        
        result = client.chat_postMessage(
            channel=channel_id,
            thread_ts=message_ts,  # This makes it a threaded reply
            text=f"📋 {canvas_url}\n\n✨ AI-generated video summary with precise timestamps ready!",
            unfurl_links=True,
            unfurl_media=True
        )
        
        print(f"🔍 Slack API response for threaded reply:")
        print(f"   - ok: {result.get('ok')}")
        print(f"   - error: {result.get('error')}")
        print(f"   - ts: {result.get('ts')}")
        print(f"   - thread_ts: {result.get('thread_ts')}")
        print(f"   - full response: {result.data}")
        
        if result.get("ok"):
            print(f"✅ Posted Canvas link as threaded reply to message {message_ts}")
            return True
        else:
            print(f"❌ Failed to post threaded Canvas reply: {result.get('error')}")
            return False
            
    except Exception as e:
        print(f"❌ Error posting threaded Canvas reply: {str(e)}")
        return False

def post_canvas_notification(video_info, canvas_id, config):
    """Post a notification message with link to the Canvas."""
    try:
        from slack_sdk import WebClient
        
        bot_token = config['slack_settings']['bot_token']
        channel_id = config['slack_settings']['channel_id']
        
        if not bot_token or not channel_id:
            print("Missing Slack configuration for Canvas notification")
            return False
        
        client = WebClient(token=bot_token)
        
        video_title = video_info.get('title', 'Unknown Video')
        video_duration = video_info.get('duration', 'Unknown')
        
        # Get workspace info to construct proper Canvas URL
        workspace_domain = 'vq8'  # Default fallback
        team_id = None
        
        try:
            # Get team ID from auth test (this should work with current scopes)
            auth_info = client.auth_test()
            print(f"🔍 Auth info: {auth_info}")
            team_id = auth_info.get('team_id')
            workspace_url = auth_info.get('url', '')
            
            if workspace_url:
                # Extract domain from URL like https://vq8.slack.com/
                import re
                match = re.search(r'https://([^.]+)\.slack\.com', workspace_url)
                if match:
                    workspace_domain = match.group(1)
                    print(f"🔍 Extracted domain from auth URL: {workspace_domain}")
            
            # Try to get team info for additional validation (might fail due to missing scope)
            try:
                team_info = client.team_info()
                print(f"🔍 Team info: {team_info}")
                team_data = team_info.get('team', {})
                if team_data.get('domain'):
                    workspace_domain = team_data.get('domain')
                    print(f"🔍 Got domain from team info: {workspace_domain}")
            except Exception as team_error:
                print(f"🔍 Team info failed (expected): {team_error}")
            
        except Exception as e:
            print(f"⚠️ Error getting workspace info: {e}")
            team_id = 'T02L2C5BJ'  # Fallback team ID from your example
        
        # Canvas URL format is https://WORKSPACE.slack.com/docs/TEAM_ID/CANVAS_ID
        if not team_id:
            team_id = 'T02L2C5BJ'  # Fallback team ID from your example
            
        canvas_url = f"https://{workspace_domain}.slack.com/docs/{team_id}/{canvas_id}"
        print(f"🔍 Generated Canvas URL: {canvas_url}")
        
        message_text = f"📋 <{canvas_url}|{video_title}> • {video_duration}"
        
        result = client.chat_postMessage(
            channel=channel_id,
            text=message_text,
            unfurl_links=False,
            unfurl_media=False
        )
        
        if result.get("ok"):
            print(f"✅ Posted Canvas notification to channel: {channel_id}")
            return True
        else:
            print(f"❌ Failed to post Canvas notification: {result.get('error')}")
            return False
            
    except Exception as e:
        print(f"❌ Error posting Canvas notification: {str(e)}")
        return False

def post_summary_to_channel(video_info, summary, timestamps, config):
    """Post video summary as regular Slack message when Canvas is not available."""
    try:
        from slack_sdk import WebClient
        from slack_sdk.errors import SlackApiError
        
        bot_token = config['slack_settings']['bot_token']
        channel_id = config['slack_settings']['channel_id']
        
        if not bot_token or not channel_id:
            print("Slack bot token or channel ID not configured")
            return False
        
        client = WebClient(token=bot_token)
        
        # Create a truncated summary for Slack message (limit 3000 chars)
        short_summary = summary[:2500] + "..." if len(summary) > 2500 else summary
        short_timestamps = timestamps[:1000] + "..." if len(timestamps) > 1000 else timestamps
        
        # Post summary as regular message
        result = client.chat_postMessage(
            channel=channel_id,
            text=f"📺 Video Analysis Complete: {video_info.get('title', 'Unknown')}",
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"📺 *Video Analysis Complete*\n\n*{video_info.get('title', 'Unknown')}*\n*Duration:* {format_duration(video_info.get('duration', 0))}\n*URL:* {video_info.get('url', '')}"
                    }
                },
                {
                    "type": "divider"
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*📋 Summary*\n\n{short_summary}"
                    }
                },
                {
                    "type": "divider"
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*⏰ Key Timestamps*\n\n{short_timestamps}"
                    }
                }
            ]
        )
        
        if result["ok"]:
            print(f"Successfully posted summary to channel: {channel_id}")
            return True
        else:
            print(f"Failed to post summary to channel: {result.get('error', 'Unknown error')}")
            return False
            
    except SlackApiError as e:
        print(f"Slack API error posting summary: {e.response['error']}")
        return False
    except Exception as e:
        print(f"Error posting summary to channel: {str(e)}")
        return False

def share_canvas_to_channel(canvas_id, config, video_title):
    """Share the Canvas to a Slack channel using Slack SDK."""
    try:
        from slack_sdk import WebClient
        from slack_sdk.errors import SlackApiError
        
        bot_token = config['slack_settings']['bot_token']
        channel_id = config['slack_settings']['channel_id']
        
        if not bot_token or not channel_id:
            print("Slack bot token or channel ID not configured")
            return False
        
        client = WebClient(token=bot_token)
        
        # Get workspace URL for Canvas link
        try:
            auth_result = client.auth_test()
            workspace_url = auth_result.get('url', 'https://slack.com/')
            team_id = auth_result.get('team_id', '')
            
            # Try the files URL format with origin parameters that seem to work
            canvas_url = f"{workspace_url}files/{canvas_id}?origin_team={team_id}&origin_channel={channel_id}"
            canvas_web_url = f"{workspace_url}canvas/{canvas_id}"  # Alternative format
        except:
            canvas_url = f"slack://canvas/{canvas_id}"  # Fallback app protocol
            canvas_web_url = f"https://slack.com/canvas/{canvas_id}"  # Fallback web
        
        # Set Canvas access permissions for the channel
        try:
            # Try to set Canvas access for the channel - this allows users in the channel to view it
            access_result = client.canvases_access_set(
                canvas_id=canvas_id,
                access_level="read",
                channel_ids=[channel_id]
            )
            print(f"🔍 Canvas access set for channel: {access_result}")
        except Exception as e:
            print(f"⚠️ Could not set Canvas channel access: {str(e)}")
            # Continue anyway - the Canvas might still be accessible
        
        # Try to use the share_canvas function for standalone canvases
        try:
            # Use the proper share_canvas function from Slack's API
            share_result = client.api_call(
                "functions.complete_success",
                function_execution_id=canvas_id,  # This might not work - it's for workflow functions
                outputs={"canvas_id": canvas_id}
            )
            print(f"🔍 Canvas shared using share_canvas function: {share_result}")
        except Exception as e:
            print(f"⚠️ Could not use share_canvas function: {str(e)}")
            # Try alternative sharing method
            try:
                # Alternative: Use files.share if Canvas is treated as a file
                share_result = client.files_share(
                    file=canvas_id,
                    channels=channel_id
                )
                print(f"🔍 Canvas shared as file: {share_result}")
            except Exception as e2:
                print(f"⚠️ Could not share Canvas as file: {str(e2)}")
                # Continue anyway - we'll post a message with a link
        
        # Share canvas to channel using Slack SDK
        result = client.chat_postMessage(
            channel=channel_id,
            text=f"📺 *Video Analysis Complete*\n\n*{video_title}*\n\nStreamSnap has finished processing this video. Click the canvas below to view the AI-generated summary and timestamps.",
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"📺 *Video Analysis Complete*\n\n*{video_title}*\n\nStreamSnap has finished processing this video. Click the canvas below to view the AI-generated summary and timestamps."
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"📋 *Canvas Created:* Canvas ID `{canvas_id}` - Check the channel for the shared Canvas document"
                    }
                }
            ]
        )
        
        if result["ok"]:
            print(f"Successfully shared Canvas to channel: {channel_id}")
            return True
        else:
            print(f"Failed to share Canvas to channel: {result.get('error', 'Unknown error')}")
            return False
            
    except SlackApiError as e:
        print(f"Slack API error sharing Canvas: {e.response['error']}")
        return False
    except Exception as e:
        print(f"Error sharing Canvas to channel: {str(e)}")
        return False

@app.route('/api/process-all', methods=['POST'])
def process_video_all():
    """Process video for all three outputs: summary, timestamps, transcript."""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'Missing video URL'}), 400
        
        video_url = data['url'].strip()
        if not video_url:
            return jsonify({'error': 'Empty video URL'}), 400
        
        # Clean the YouTube URL to remove playlist and other parameters
        video_url = clean_youtube_url(video_url)
        
        # Extract video ID for timestamp links
        video_id = extract_video_id(video_url)
        if not video_id:
            return jsonify({'error': 'Invalid YouTube URL'}), 400
        
        # Load configuration
        config = load_config()
        
        # Validate Azure OpenAI configuration
        if not all([
            config['ai_settings']['azure_openai_endpoint'],
            config['ai_settings']['azure_openai_api_key'],
            config['ai_settings']['azure_openai_model']
        ]):
            return jsonify({'error': 'Azure OpenAI configuration incomplete. Please check admin settings.'}), 400
        
        # Stage 1: Get video information
        print("🎬 Stage 1/5: Fetching video information...")
        video_info = get_video_info(video_url)
        print(f"✅ Video info retrieved: '{video_info['title']}' ({video_info['duration']//60}:{video_info['duration']%60:02d})")
        
        # Check video duration limit
        max_duration = config['processing_settings']['max_video_duration']
        if video_info['duration'] > max_duration:
            return jsonify({
                'error': f'Video too long ({video_info["duration"]//60}:{video_info["duration"]%60:02d}). Maximum allowed: {max_duration//60}:{max_duration%60:02d}'
            }), 400
        
        # Stage 2: Extract transcript
        print("📝 Stage 2/5: Extracting transcript...")
        transcript = None
        if config['processing_settings']['prefer_transcript']:
            print("  🔍 Searching for existing captions...")
            transcript = get_transcript(video_info)
            if transcript:
                print(f"  ✅ Found existing captions ({len(transcript)} characters)")
        
        # If no transcript found, try Whisper transcription (if enabled)
        if not transcript and config['processing_settings']['enable_whisper_transcription']:
            print("  🎤 No captions found, attempting audio transcription with Whisper...")
            transcript = transcribe_audio_with_whisper(video_url, config)
            if transcript:
                print(f"  ✅ Whisper transcription completed ({len(transcript)} characters)")
        
        if not transcript:
            # Check what's available for debugging
            subtitles = video_info.get('subtitles', {})
            auto_captions = video_info.get('automatic_captions', {})
            
            manual_langs = list(subtitles.keys())
            auto_langs = list(auto_captions.keys())
            
            if manual_langs or auto_langs:
                debug_info = []
                if manual_langs:
                    debug_info.append(f"Manual: {', '.join(manual_langs[:5])}")
                if auto_langs:
                    debug_info.append(f"Auto: {', '.join(auto_langs[:5])}")
                
                return jsonify({
                    'error': f'No English transcript found and audio transcription failed. Available captions - {"; ".join(debug_info)}.'
                }), 400
            else:
                return jsonify({
                    'error': 'No transcripts available and audio transcription failed. This video may not have audio or may be restricted.'
                }), 400
        
        # Stage 3: Generate AI summary
        print("🤖 Stage 3/5: Generating AI summary...")
        
        # Use chapter-aware summary if chapters are available
        chapters = video_info.get('chapters', [])
        if chapters:
            print(f"  📑 Using {len(chapters)} chapters for summary generation")
            summary = generate_summary_with_chapters(transcript, video_info['title'], video_id, chapters, config)
        else:
            print("  🤖 No chapters found, using standard summary generation")
            summary = generate_summary(transcript, video_info['title'], video_id, config)
        print("  ✅ Summary generated successfully")
        
        # Stage 4: Generate timestamps
        print("⏰ Stage 4/5: Generating smart timestamps...")
        
        # Try YouTube chapters first (most accurate), then Whisper timestamps, then AI analysis
        chapters = video_info.get('chapters', [])
        if chapters:
            print(f"  📑 Using {len(chapters)} YouTube chapters for precise timestamps")
            
            # Try chapter-by-chapter summaries if we have both chapters and transcript
            chapter_summaries = generate_chapter_summaries(chapters, transcript, video_id, config)
            if chapter_summaries:
                print(f"  ✨ Generated chapter-by-chapter summaries for {len(chapters)} chapters")
                timestamps = chapter_summaries['timestamp_list']
                # Replace the summary with chapter-by-chapter summaries
                summary = chapter_summaries['summary_sections']
            else:
                print(f"  📑 Using standard chapter timestamps")
                timestamps = generate_timestamps_from_chapters(chapters, video_id)
        else:
            # Try Whisper transcription with timestamps as fallback
            try:
                print("  🎵 No chapters found, trying Whisper transcription with timestamps...")
                whisper_data = transcribe_audio_with_whisper_timestamps(video_url, config)
                if whisper_data and whisper_data.get('segments'):
                    print(f"  🎯 Using Whisper segments for precise timestamps ({len(whisper_data['segments'])} segments)")
                    whisper_result = generate_timestamps_from_whisper(whisper_data, summary, video_id, config)
                    if whisper_result and isinstance(whisper_result, dict):
                        # Replace summary with segment summaries and extract timestamps
                        summary = whisper_result['summary_sections']
                        timestamps = whisper_result['timestamp_list']
                    else:
                        # Fallback to AI analysis
                        timestamps = generate_timestamps(transcript, video_info['title'], video_id, config)
                else:
                    print("  🤖 Whisper segments not available, using AI analysis of transcript")
                    timestamps = generate_timestamps(transcript, video_info['title'], video_id, config)
            except Exception as e:
                print(f"  ⚠️ Whisper transcription failed: {str(e)}")
                print("  🤖 Falling back to AI analysis of transcript")
                timestamps = generate_timestamps(transcript, video_info['title'], video_id, config)
        print("  ✅ Timestamps generated successfully")
        
        # Stage 5: Final processing
        print("🔧 Stage 5/5: Finalizing results...")
        print("  📝 Formatting transcript for better readability...")
        formatted_transcript = format_transcript(transcript)
        print("  ✅ Processing complete!")
        
        # Format response
        response = {
            'success': True,
            'video_info': {
                'title': video_info['title'],
                'duration': f"{video_info['duration']//60}:{video_info['duration']%60:02d}",
                'thumbnail': video_info['thumbnail'],
                'view_count': video_info.get('view_count', 0)
            },
            'results': {
                'summary': summary,
                'timestamps': timestamps,
                'transcript': formatted_transcript
            }
        }
        
        print("🎉 All processing stages completed successfully!")
        
        return jsonify(response)
        
    except Exception as e:
        print(f"❌ Error processing video: {e}")
        print(traceback.format_exc())
        return jsonify({'error': f'Processing failed: {str(e)}'}), 500

def save_discovered_channel(channel_id, channel_type="unknown"):
    """Save discovered channel to config for persistence across reboots."""
    try:
        config = load_config()
        slack_settings = config.get('slack_settings', {})
        
        # Get current discovered channels
        discovered = slack_settings.get('discovered_channels', {})
        
        # Add new channel with metadata
        if channel_id not in discovered:
            discovered[channel_id] = {
                'type': channel_type,
                'discovered_at': time.time(),
                'last_seen': time.time()
            }
            print(f"💾 Discovered new channel: {channel_id} ({channel_type})")
        else:
            # Update last seen time
            discovered[channel_id]['last_seen'] = time.time()
        
        # Save back to config
        slack_settings['discovered_channels'] = discovered
        config['slack_settings'] = slack_settings
        
        # Write to config file
        config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.yaml')
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
            
    except Exception as e:
        print(f"⚠️  Failed to save discovered channel {channel_id}: {e}")

def remove_discovered_channel(channel_id):
    """Remove channel from discovered channels when bot is removed."""
    try:
        config = load_config()
        slack_settings = config.get('slack_settings', {})
        discovered = slack_settings.get('discovered_channels', {})
        
        if channel_id in discovered:
            del discovered[channel_id]
            slack_settings['discovered_channels'] = discovered
            config['slack_settings'] = slack_settings
            
            # Write to config file
            config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.yaml')
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            
            print(f"🗑️  Removed channel from discovered list: {channel_id}")
        
    except Exception as e:
        print(f"⚠️  Failed to remove discovered channel {channel_id}: {e}")

def log_activity(activity_type, channel_id, user_id, video_title, video_url, details=None):
    """Log Slack activity for dashboard display."""
    config = load_config()
    try:
        slack_settings = config.get('slack_settings', {})
        activity_log = slack_settings.get('recent_activity', [])
        
        # Create activity record
        activity = {
            'timestamp': time.time(),
            'type': activity_type,  # 'video_processed', 'canvas_created', 'transcript_generated'
            'channel_id': channel_id,
            'user_id': user_id,
            'video_title': video_title,
            'video_url': video_url,
            'details': details or {}
        }
        
        # Add to beginning of list (newest first)
        activity_log.insert(0, activity)
        
        # Keep only last 30 days of activities
        thirty_days_ago = time.time() - (30 * 24 * 60 * 60)
        activity_log = [a for a in activity_log if a.get('timestamp', 0) > thirty_days_ago]
        
        slack_settings['recent_activity'] = activity_log
        config['slack_settings'] = slack_settings
        
        save_config(config)
        print(f"📊 Logged activity: {activity_type} in {channel_id}")
        
    except Exception as e:
        print(f"⚠️  Failed to log activity: {e}")

def get_slack_activity_data():
    """Get comprehensive Slack activity data for dashboard."""
    config = load_config()
    slack_settings = config.get('slack_settings', {})
    
    # Get discovered channels with metadata
    discovered = slack_settings.get('discovered_channels', {})
    channels_data = []
    
    for channel_id, info in discovered.items():
        channel_data = {
            'id': channel_id,
            'type': info.get('type', 'unknown'),
            'first_seen': info.get('first_seen', 0),
            'last_seen': info.get('last_seen', 0),
            'activity_count': 0,
            'recent_videos': []
        }
        channels_data.append(channel_data)
    
    # Get recent activity
    activity_log = slack_settings.get('recent_activity', [])
    
    # Count activities per channel and add recent videos
    for activity in activity_log:
        for channel in channels_data:
            if channel['id'] == activity['channel_id']:
                channel['activity_count'] += 1
                if len(channel['recent_videos']) < 5:  # Keep last 5 videos per channel
                    channel['recent_videos'].append({
                        'title': activity['video_title'],
                        'url': activity['video_url'],
                        'timestamp': activity['timestamp'],
                        'user_id': activity['user_id'],
                        'type': activity['type']
                    })
    
    return {
        'channels': channels_data,
        'recent_activity': activity_log[:50],  # Last 50 activities overall (30 days)
        'total_channels': len(discovered),
        'total_activities': len(activity_log)
    }

def seed_activity_from_logs():
    """Seed activity history from container logs and existing data."""
    try:
        import re
        import subprocess
        from datetime import datetime, timedelta
        
        print("🌱 Seeding activity history from container logs...")
        
        # Get last 30 days of container logs
        try:
            # Try to get logs from current container
            result = subprocess.run(['docker', 'logs', '--since', '30d', 'streamsnap'], 
                                  capture_output=True, text=True, timeout=30)
            logs = result.stdout + result.stderr
        except Exception as e:
            print(f"⚠️  Could not get container logs: {e}")
            return
        
        # Parse logs for video processing activities
        video_pattern = r'🎬.*?Fetching video information.*?https://.*?youtube\.com/watch\?v=([a-zA-Z0-9_-]{11})'
        canvas_pattern = r'📋 Canvas created successfully.*?Canvas ID: ([a-zA-Z0-9]+)'
        transcript_pattern = r'📝 Using (transcript|captions)'
        
        activities_found = 0
        
        for line in logs.split('\n'):
            # Look for video processing
            if '🎬' in line and 'youtube.com' in line:
                video_match = re.search(video_pattern, line)
                if video_match:
                    video_id = video_match.group(1)
                    
                    # Estimate timestamp from log (rough approximation)
                    # In real implementation, you'd parse the actual log timestamps
                    estimated_time = time.time() - (activities_found * 3600)  # Spread over time
                    
                    # Log synthetic activity
                    log_activity(
                        activity_type='video_processed',
                        channel_id='seeded_data',
                        user_id='system',
                        video_title=f'Video {video_id}',
                        video_url=f'https://youtube.com/watch?v={video_id}',
                        details={'seeded': True, 'estimated_time': estimated_time}
                    )
                    activities_found += 1
                    
                    if activities_found >= 20:  # Limit seeded data
                        break
        
        print(f"✅ Seeded {activities_found} activities from logs")
        
    except Exception as e:
        print(f"⚠️  Failed to seed activity from logs: {e}")

def get_target_channels(slack_settings):
    """Parse channel configuration to support multiple channels and DMs."""
    # Check if auto-detect mode is enabled
    auto_detect = slack_settings.get('auto_detect_channels', False)
    
    if auto_detect:
        # Get discovered channels from persistent storage
        discovered = slack_settings.get('discovered_channels', {})
        channels = set(discovered.keys())
        
        if channels:
            channel_types = []
            for ch in channels:
                ch_info = discovered.get(ch, {})
                ch_type = ch_info.get('type', 'unknown')
                if ch.startswith('D'):
                    channel_types.append(f"{ch} (DM)")
                elif ch.startswith('C'):
                    channel_types.append(f"{ch} (Channel)")
                else:
                    channel_types.append(f"{ch} ({ch_type})")
            print(f"🔍 Auto-detect mode: Processing YouTube URLs from discovered channels: {', '.join(channel_types)}")
        else:
            print("🔍 Auto-detect mode: No channels discovered yet - will discover as messages are received")
        
        return channels if channels else "auto"  # Return discovered channels or auto mode
    
    # Manual channel configuration
    channels = set()
    
    # Handle legacy single channel_id (backward compatibility)
    channel_id = slack_settings.get('channel_id', '')
    if channel_id and channel_id.strip():
        # Support comma-separated channel IDs
        for ch in channel_id.split(','):
            ch = ch.strip()
            if ch:
                channels.add(ch)
    
    # Handle new channels list format
    channels_list = slack_settings.get('channels', [])
    if isinstance(channels_list, list):
        for ch in channels_list:
            if ch and ch.strip():
                channels.add(ch.strip())
    
    # Log the channels we're listening to
    if channels:
        channel_types = []
        for ch in channels:
            if ch.startswith('D'):
                channel_types.append(f"{ch} (DM)")
            elif ch.startswith('C'):
                channel_types.append(f"{ch} (Channel)")
            else:
                channel_types.append(f"{ch} (Unknown)")
        print(f"📢 Manual mode: Listening to specific channels: {', '.join(channel_types)}")
    else:
        print("⚠️  No channels configured - bot will not process any messages")
    
    return channels

def verify_slack_signature(request_data, timestamp, signature, signing_secret):
    """Verify that requests are coming from Slack using the signing secret."""
    if not signing_secret:
        return False
    
    # Create the signature base string
    sig_basestring = f'v0:{timestamp}:{request_data}'
    
    # Create the expected signature
    expected_signature = 'v0=' + hmac.new(
        signing_secret.encode(),
        sig_basestring.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Compare signatures securely
    return hmac.compare_digest(expected_signature, signature)

def detect_youtube_urls_in_text(text):
    """Extract YouTube URLs from text."""
    youtube_patterns = [
        r'https?://(?:www\.)?youtube\.com/watch\?v=([a-zA-Z0-9_-]+)',
        r'https?://youtu\.be/([a-zA-Z0-9_-]+)',
        r'https?://(?:www\.)?youtube\.com/embed/([a-zA-Z0-9_-]+)',
        r'https?://(?:m\.)?youtube\.com/watch\?v=([a-zA-Z0-9_-]+)'
    ]
    
    urls = []
    for pattern in youtube_patterns:
        matches = re.finditer(pattern, text)
        for match in matches:
            urls.append(match.group(0))
    
    return urls

def process_video_for_slack(video_url, config):
    """Process video for Slack integration - returns dict instead of Flask response."""
    try:
        # Clean the YouTube URL to remove playlist and other parameters
        video_url = clean_youtube_url(video_url)
        
        # Extract video ID for timestamp links
        video_id = extract_video_id(video_url)
        if not video_id:
            return {'success': False, 'error': 'Invalid YouTube URL'}
        
        # Validate Azure OpenAI configuration
        if not all([
            config['ai_settings']['azure_openai_endpoint'],
            config['ai_settings']['azure_openai_api_key'],
            config['ai_settings']['azure_openai_model']
        ]):
            return {'success': False, 'error': 'Azure OpenAI configuration incomplete'}
        
        # Stage 1: Get video information
        print("🎬 Stage 1/5: Fetching video information...")
        video_info = get_video_info(video_url)
        print(f"✅ Video info retrieved: '{video_info['title']}' ({video_info['duration']//60}:{video_info['duration']%60:02d})")
        
        # Check video duration limit
        max_duration = config['processing_settings']['max_video_duration']
        if video_info['duration'] > max_duration:
            return {
                'success': False, 
                'error': f'Video too long ({video_info["duration"]//60}:{video_info["duration"]%60:02d}). Maximum allowed: {max_duration//60}:{max_duration%60:02d}'
            }
        
        # Stage 2: Extract transcript
        print("📝 Stage 2/5: Extracting transcript...")
        transcript = None
        if config['processing_settings']['prefer_transcript']:
            print("  🔍 Searching for existing captions...")
            transcript = get_transcript(video_info)
        
        if not transcript and config['processing_settings']['enable_whisper_transcription']:
            print("  🎤 Using Whisper for transcription...")
            transcript = transcribe_audio_with_whisper(video_url, config)
        
        if not transcript:
            return {'success': False, 'error': 'Could not extract transcript from video'}
        
        print(f"✅ Transcript extracted: {len(transcript)} characters")
        
        # Stage 3: Generate summary
        print("📄 Stage 3/5: Generating summary...")
        
        # Use chapter-aware summary if chapters are available
        chapters = video_info.get('chapters', [])
        if chapters:
            print(f"  📑 Using {len(chapters)} chapters for summary generation")
            summary = generate_summary_with_chapters(transcript, video_info['title'], video_id, chapters, config)
        else:
            print("  🤖 No chapters found, using standard summary generation")
            summary = generate_summary(transcript, video_info['title'], video_id, config)
        print("✅ Summary generated")
        
        # Stage 4: Generate timestamps  
        print("⏰ Stage 4/5: Generating timestamps...")
        
        # Try YouTube chapters first (most accurate), then Whisper timestamps, then AI analysis
        chapters = video_info.get('chapters', [])
        if chapters:
            print(f"  📑 Using {len(chapters)} YouTube chapters for precise timestamps")
            
            # Try chapter-by-chapter summaries if we have both chapters and transcript
            chapter_summaries = generate_chapter_summaries(chapters, transcript, video_id, config)
            if chapter_summaries:
                print(f"  ✨ Generated chapter-by-chapter summaries for {len(chapters)} chapters")
                timestamps = chapter_summaries['timestamp_list']
                # Replace the summary with chapter-by-chapter summaries
                summary = chapter_summaries['summary_sections']
            else:
                print(f"  📑 Using standard chapter timestamps")
                timestamps = generate_timestamps_from_chapters(chapters, video_id)
        else:
            # Try Whisper transcription with timestamps as fallback
            try:
                print("  🎵 No chapters found, trying Whisper transcription with timestamps...")
                whisper_data = transcribe_audio_with_whisper_timestamps(video_url, config)
                if whisper_data and whisper_data.get('segments'):
                    print(f"  🎯 Using Whisper segments for precise timestamps ({len(whisper_data['segments'])} segments)")
                    whisper_result = generate_timestamps_from_whisper(whisper_data, summary, video_id, config)
                    if whisper_result and isinstance(whisper_result, dict):
                        # Replace summary with segment summaries and extract timestamps
                        summary = whisper_result['summary_sections']
                        timestamps = whisper_result['timestamp_list']
                    else:
                        # Fallback to AI analysis
                        timestamps = generate_timestamps(transcript, video_info['title'], video_id, config)
                else:
                    print("  🤖 Whisper segments not available, using AI analysis of transcript")
                    timestamps = generate_timestamps(transcript, video_info['title'], video_id, config)
            except Exception as e:
                print(f"  ⚠️ Whisper transcription failed: {str(e)}")
                print("  🤖 Falling back to AI analysis of transcript")
                timestamps = generate_timestamps(transcript, video_info['title'], video_id, config)
        print("✅ Timestamps generated")
        
        # Stage 5: Create and share Slack Canvas (with fallback)
        print("📋 Stage 5/5: Creating Slack Canvas...")
        canvas_content = create_slack_canvas_content(video_info, summary, timestamps, transcript)
        canvas_id = create_slack_canvas(canvas_content, config)
        
        if canvas_id:
            print("✅ Canvas created successfully - Canvas will be visible in channel automatically")
        else:
            print("❌ Failed to create Slack Canvas, trying fallback message...")
            fallback_success = post_summary_to_channel(video_info, summary, timestamps, config)
            if fallback_success:
                print("✅ Posted summary as regular Slack message")
            else:
                print("❌ Failed to post summary to Slack")
            canvas_id = None
        
        return {
            'success': True,
            'video_info': video_info,
            'results': {
                'summary': summary,
                'timestamps': timestamps,
                'transcript': transcript
            },
            'canvas_id': canvas_id
        }
    
    except Exception as e:
        print(f"❌ Error processing video: {str(e)}")
        traceback.print_exc()
        return {'success': False, 'error': str(e)}

def test_canvas_creation(channel, config):
    """Test Canvas creation with sample content."""
    try:
        print("🧪 Testing Canvas creation...")
        
        # Create sample video info for testing
        sample_video_info = {
            'title': 'Canvas Test - StreamSnap Functionality',
            'duration': '5:30',
            'url': 'https://www.youtube.com/watch?v=test123'
        }
        
        sample_summary = """This is a test of the StreamSnap Canvas creation functionality.

## Test Summary

This Canvas was created to verify that the Canvas API is working properly with your Slack workspace. If you can see this message, the Canvas creation is functioning correctly.

**Key Points:**
- Canvas creation: Working
- Markdown formatting: Supported  
- Fallback messaging: Available

## Next Steps

Try posting a real YouTube URL to see the full video processing pipeline in action!"""

        sample_timestamps = """**[0:00](https://www.youtube.com/watch?v=test123&t=0s)** - Test Beginning
**[1:30](https://www.youtube.com/watch?v=test123&t=90s)** - Canvas Creation Test
**[3:00](https://www.youtube.com/watch?v=test123&t=180s)** - Functionality Verification
**[5:30](https://www.youtube.com/watch?v=test123&t=330s)** - Test Complete"""
        
        # Create Canvas content
        canvas_content = create_slack_canvas_content(sample_video_info, sample_summary, sample_timestamps, "Test transcript content...")
        
        # Create a modified config with the target channel
        test_config = config.copy()
        test_config['slack_settings'] = config['slack_settings'].copy()
        test_config['slack_settings']['channel_id'] = channel
        
        # Try to create Canvas
        canvas_id = create_slack_canvas(canvas_content, test_config)
        
        if canvas_id:
            print(f"✅ Test Canvas created successfully: {canvas_id}")
            # Post notification message with Canvas link
            notification_success = post_canvas_notification(sample_video_info, canvas_id, test_config)
            if notification_success:
                print("✅ Test Canvas notification posted to channel")
            else:
                print("⚠️ Test Canvas created but failed to post notification")
        else:
            print("❌ Test Canvas creation failed, trying fallback message...")
            fallback_success = post_summary_to_channel(sample_video_info, sample_summary, sample_timestamps, test_config)
            if fallback_success:
                print("✅ Test fallback message posted successfully")
            else:
                print("❌ Test fallback message failed")
        
        print("🧪 Canvas test completed")
        
    except Exception as e:
        print(f"❌ Error in Canvas test: {e}")

def process_video_async(url, config, target_channel=None, message_ts=None, user_id=None):
    """Process video in background thread."""
    global processing_urls
    clean_url = None
    current_thread = threading.current_thread()
    thread_id = f"{current_thread.ident}_{int(time.time())}"
    
    try:
        # Check if graceful shutdown is requested
        if shutdown_requested:
            print(f"🛑 Graceful shutdown in progress - rejecting new processing for: {url}")
            return
            
        print(f"🔄 Background processing started for: {url} (thread: {thread_id})")
        
        # Clean the URL
        video_id = extract_video_id(url)
        if not video_id:
            print(f"❌ Invalid YouTube URL: {url}")
            return
        
        clean_url = f"https://www.youtube.com/watch?v={video_id}"
        
        # Register this thread for safe restart tracking
        register_processing_thread(thread_id, current_thread, clean_url, user_id)
        
        # Deduplication check: prevent processing same URL within 10 minutes
        current_time = time.time()
        if clean_url in processing_urls:
            time_since_started = current_time - processing_urls[clean_url]
            if time_since_started < 600:  # 10 minutes
                print(f"🔄 Skipping duplicate processing for {clean_url} (started {time_since_started:.1f}s ago)")
                return
            else:
                # Remove old entry if more than 10 minutes
                del processing_urls[clean_url]
        
        # Mark this URL as being processed
        processing_urls[clean_url] = current_time
        print(f"🔄 Added {clean_url} to processing queue")
        
        # Process the video directly
        response = process_video_for_slack(clean_url, config)
        
        if not response.get('success'):
            print(f"❌ Video processing failed: {response.get('error')}")
            return
        
        # Generate Canvas if Slack is configured
        config_slack = config['slack_settings']
        # Use target_channel if provided, otherwise fall back to configured channel
        canvas_channel = target_channel or config_slack.get('channel_id')
        if config_slack.get('bot_token') and canvas_channel:
            print("📋 Creating Slack Canvas...")
            
            summary = response['results']['summary']
            timestamps = response['results']['timestamps']
            transcript = response['results']['transcript']
            
            canvas_content = create_slack_canvas_content(response['video_info'], summary, timestamps, transcript)
            
            # Create a modified config with the target channel
            canvas_config = config.copy()
            canvas_config['slack_settings'] = config_slack.copy()
            canvas_config['slack_settings']['channel_id'] = canvas_channel
            
            canvas_id = create_slack_canvas(canvas_content, canvas_config)
            
            if canvas_id:
                print(f"✅ Slack Canvas created successfully: {canvas_id}")
                
                # Log activity for dashboard
                log_activity(
                    activity_type='canvas_created',
                    channel_id=canvas_channel,
                    user_id=user_id or 'unknown',
                    video_title=response['video_info'].get('title', 'Unknown Video'),
                    video_url=clean_url,
                    details={
                        'canvas_id': canvas_id,
                        'has_chapters': len(response['video_info'].get('chapters', [])) > 0,
                        'has_transcript': bool(response['results'].get('transcript')),
                        'duration': response['video_info'].get('duration', 0)
                    }
                )
                
                # Post threaded Canvas reply if we have message timestamp, otherwise fallback to simple link
                if message_ts:
                    canvas_link_success = post_threaded_canvas_reply(canvas_id, canvas_config, canvas_channel, message_ts)
                    if canvas_link_success:
                        print("✅ Posted Canvas link as threaded reply")
                    else:
                        print("⚠️ Canvas created but failed to post threaded reply")
                else:
                    # Fallback to simple Canvas link message for backwards compatibility
                    canvas_link_success = post_simple_canvas_link(canvas_id, canvas_config)
                    if canvas_link_success:
                        print("✅ Posted Canvas link to channel")
                    else:
                        print("⚠️ Canvas created but failed to post link")
            else:
                print("❌ Failed to create Slack Canvas, trying fallback message...")
                fallback_success = post_summary_to_channel(response['video_info'], summary, timestamps, canvas_config)
                if fallback_success:
                    print("✅ Posted summary as regular Slack message")
                else:
                    print("❌ Failed to post summary to Slack")
        
        print(f"✅ Background processing completed for: {url}")
        
    except Exception as e:
        print(f"❌ Error in background processing: {e}")
        print(traceback.format_exc())
    finally:
        # Clean up processing URLs tracking
        if clean_url and clean_url in processing_urls:
            del processing_urls[clean_url]
            print(f"🧹 Removed {clean_url} from processing queue")
        
        # Unregister thread from safe restart tracking
        unregister_processing_thread(thread_id)

@app.route('/slack/events', methods=['POST'])
def slack_events():
    """Handle Slack Events API webhooks for auto-detecting YouTube URLs."""
    try:
        # Get request data
        request_data = request.get_data(as_text=True)
        timestamp = request.headers.get('X-Slack-Request-Timestamp', '')
        signature = request.headers.get('X-Slack-Signature', '')
        
        # Load config to get signing secret (prioritize environment variables)
        config = load_config()
        env_secret = os.getenv('SLACK_SIGNING_SECRET', '')
        config_secret = config['slack_settings'].get('signing_secret', '')
        signing_secret = env_secret or config_secret
        
        # Debug logging
        print(f"🔍 Debug: env_secret = '{env_secret}' (length: {len(env_secret)})")
        print(f"🔍 Debug: config_secret = '{config_secret}' (length: {len(config_secret)})")
        print(f"🔍 Debug: final signing_secret = '{signing_secret}' (length: {len(signing_secret)})")
        print(f"🔍 Debug: signing_secret.strip() = '{signing_secret.strip()}' (length: {len(signing_secret.strip())})")
        
        # Verify request is from Slack
        # Skip verification only in development mode when explicitly disabled
        dev_mode = os.getenv('ENVIRONMENT', 'production') == 'development'
        skip_verification = os.getenv('SLACK_SKIP_VERIFICATION', 'false').lower() == 'true'
        
        if signing_secret and signing_secret.strip() and not (dev_mode and skip_verification):
            print("🔐 Performing Slack signature verification")
            if not verify_slack_signature(request_data, timestamp, signature, signing_secret):
                print("❌ Invalid Slack signature")
                return jsonify({'error': 'Invalid signature'}), 403
            print("✅ Slack signature verification passed")
        else:
            if not signing_secret or not signing_secret.strip():
                print("⚠️  No Slack signing secret configured - webhook disabled")
                return jsonify({'error': 'Slack integration not configured'}), 400
            else:
                print("⚠️  Slack signature verification skipped (development mode)")
        
        # Parse JSON
        event_data = request.get_json()
        
        # Handle URL verification challenge
        if event_data.get('type') == 'url_verification':
            return jsonify({'challenge': event_data['challenge']})
        
        # Handle message events
        if event_data.get('type') == 'event_callback':
            event = event_data.get('event', {})
            event_type = event.get('type', '')
            
            # Handle channel membership events (bot invited/removed)
            if event_type in ['member_joined_channel', 'member_left_channel']:
                user_id = event.get('user', '')
                channel_id = event.get('channel', '')
                
                # Check if this is our bot (you'll need to configure your bot's user ID)
                bot_user_id = config['slack_settings'].get('bot_user_id', '')
                if user_id == bot_user_id:
                    if event_type == 'member_joined_channel':
                        channel_type = "Channel"
                        save_discovered_channel(channel_id, channel_type)
                        print(f"🎉 Bot invited to channel: {channel_id}")
                    elif event_type == 'member_left_channel':
                        # Remove from discovered channels
                        remove_discovered_channel(channel_id)
                        print(f"👋 Bot removed from channel: {channel_id}")
            
            # Only process regular messages (not from bots)
            elif (event_type == 'message' and 
                  event.get('subtype') is None and 
                  not event.get('bot_id')):
                
                text = event.get('text', '')
                channel = event.get('channel', '')
                user = event.get('user', '')
                message_ts = event.get('ts', '')
                
                # Early optimization: only process if message contains YouTube URLs or test commands
                has_youtube_urls = bool(detect_youtube_urls_in_text(text))
                is_test_command = '@streamsnap test canvas' in text.lower() or 'test canvas' in text.lower()
                
                if not has_youtube_urls and not is_test_command:
                    # Skip processing if no YouTube URLs and no test commands
                    return jsonify({'status': 'ok'})
                
                # Check if this channel is in our configured channels list
                target_channels = get_target_channels(config['slack_settings'])
                should_process = False
                
                if target_channels == "auto":
                    # Auto-detect mode: process messages from any channel
                    should_process = True
                elif target_channels and channel in target_channels:
                    # Manual mode: only process configured channels
                    should_process = True
                
                if should_process:
                    # In auto-detect mode, save discovered channels for persistence
                    if target_channels == "auto" or (isinstance(target_channels, set) and config['slack_settings'].get('auto_detect_channels', False)):
                        channel_type = "DM" if channel.startswith('D') else "Channel"
                        save_discovered_channel(channel, channel_type)
                    
                    # Detect YouTube URLs in the message
                    youtube_urls = detect_youtube_urls_in_text(text)
                    
                    if youtube_urls:
                        print(f"🎬 Detected YouTube URLs in Slack: {youtube_urls}")
                        
                        # Process each URL in background
                        for url in youtube_urls:
                            thread = threading.Thread(
                                target=process_video_async, 
                                args=(url, config, channel, message_ts, user)
                            )
                            thread.daemon = True
                            thread.start()
                        
                        # Send immediate acknowledgment to Slack
                        return jsonify({'status': 'processing'}), 200
                    
                    elif is_test_command:
                        print(f"🧪 Test command detected in channel: {channel}")
                        
                        # Test Canvas creation with sample content
                        thread = threading.Thread(
                            target=test_canvas_creation, 
                            args=(channel, config)
                        )
                        thread.daemon = True
                        thread.start()
                        
                        return jsonify({'status': 'testing'}), 200
            
            # Handle link_shared events (more efficient than processing all messages)
            elif event_type == 'link_shared':
                links = event.get('links', [])
                channel = event.get('channel', '')
                user = event.get('user', '')
                # Try multiple possible fields for message timestamp
                message_ts = event.get('message_ts', '') or event.get('ts', '') or event.get('event_ts', '')
                
                # Check if this link was shared within an existing thread
                thread_ts = event.get('thread_ts', '')
                is_in_thread = bool(thread_ts)
                
                # Check the source of the link_shared event
                event_source = event.get('source', '')
                
                print(f"🔗 Link shared event received in channel {channel}")
                print(f"🔍 Event source: '{event_source}'")
                print(f"🔍 message_ts extracted: '{message_ts}'")
                print(f"🔍 thread_ts: '{thread_ts}' (is_in_thread: {is_in_thread})")
                
                # Skip events from composer (these are from pasting while typing, not posting)
                if event_source == 'composer':
                    print(f"⏭️ Skipping link_shared event from composer (URL pasted while typing, not posted yet)")
                    return jsonify({'status': 'skipped'}), 200
                
                # Check if this channel is in our configured channels list
                target_channels = get_target_channels(config['slack_settings'])
                should_process = False
                
                # Check if auto-detect mode is enabled
                auto_detect = config['slack_settings'].get('auto_detect_channels', False)
                
                if target_channels == "auto":
                    # Auto-detect mode: process links from any channel
                    should_process = True
                elif auto_detect:
                    # Auto-detect mode with discovered channels: add current channel and process
                    channel_type = "DM" if channel.startswith('D') else "Channel"
                    save_discovered_channel(channel, channel_type)
                    should_process = True
                    print(f"🔍 Auto-detect: Added new channel {channel} and processing YouTube URLs")
                elif target_channels and channel in target_channels:
                    # Manual mode: only process configured channels
                    should_process = True
                
                if should_process:
                    # Channel already saved above in auto-detect mode, so no need to save again
                    
                    # Extract YouTube URLs from shared links
                    youtube_urls = []
                    for link in links:
                        url = link.get('url', '')
                        if 'youtube.com' in url or 'youtu.be' in url:
                            youtube_urls.append(url)
                    
                    if youtube_urls:
                        print(f"🎬 Detected YouTube URLs from link_shared: {youtube_urls}")
                        
                        # Process each URL in background
                        for url in youtube_urls:
                            # If the link was posted in an existing thread, don't create threaded replies
                            # Only create threaded replies for links posted directly to the channel
                            thread_message_ts = None if is_in_thread else message_ts
                            
                            if is_in_thread:
                                print(f"📝 Link posted in existing thread - Canvas will appear as standalone message")
                            else:
                                print(f"📝 Link posted to channel - Canvas will appear as threaded reply to {message_ts}")
                            
                            thread = threading.Thread(
                                target=process_video_async, 
                                args=(url, config, channel, thread_message_ts)  # Pass message_ts only if not in thread
                            )
                            thread.daemon = True
                            thread.start()
                        
                        # Send immediate acknowledgment to Slack
                        return jsonify({'status': 'processing'}), 200
                    else:
                        print("🔗 Non-YouTube links shared, ignoring")
        
        # Default response for other events
        return jsonify({'status': 'ok'}), 200
        
    except Exception as e:
        print(f"❌ Error handling Slack event: {e}")
        print(traceback.format_exc())
        return jsonify({'error': 'Internal error'}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)