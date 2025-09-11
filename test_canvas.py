#!/usr/bin/env python3
"""
Test script to debug Slack Canvas API directly
"""

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import json

# Use the credentials from environment variables
import os
BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN", "your-slack-bot-token-here")

def test_canvas_creation():
    """Test Canvas creation directly with Slack SDK"""
    client = WebClient(token=BOT_TOKEN)
    
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

    try:
        print("🧪 Testing Canvas creation with Slack SDK...")
        print(f"🔍 Bot token: {BOT_TOKEN[:20]}...")
        print(f"🔍 Content length: {len(test_content)} chars")
        
        result = client.canvases_create(
            title="📺 Canvas Test - StreamSnap Functionality",
            document_content={
                "type": "markdown",
                "markdown": test_content
            }
        )
        
        print(f"🔍 Full API Response:")
        print(f"   Type: {type(result)}")
        print(f"   Data: {result}")
        
        if hasattr(result, 'data'):
            print(f"   Result.data: {result.data}")
            
        # Try to pretty print if it's a dict
        if isinstance(result, dict):
            print(f"   JSON formatted: {json.dumps(result, indent=2)}")
        
        if result and result.get("ok"):
            canvas_data = result.get("canvas", {})
            canvas_id = canvas_data.get("id") if canvas_data else None
            print(f"✅ Success! Canvas ID: {canvas_id}")
            if canvas_id:
                # Try to get Canvas details
                canvas_info = client.canvases_access_set_for_user(
                    canvas_id=canvas_id,
                    access_level="write"
                )
                print(f"🔍 Canvas access result: {canvas_info}")
                return canvas_id
            else:
                print("❌ Canvas created but no ID returned")
        else:
            error = result.get('error', 'Unknown error') if result else 'No response'
            print(f"❌ Canvas creation failed: {error}")
            
    except SlackApiError as e:
        print(f"❌ Slack API Error:")
        print(f"   Error code: {e.response.get('error', 'unknown')}")
        print(f"   Full response: {json.dumps(e.response, indent=2)}")
    except Exception as e:
        print(f"❌ General Error: {str(e)}")
        import traceback
        traceback.print_exc()

def test_bot_auth():
    """Test if the bot token is valid and what scopes it has"""
    client = WebClient(token=BOT_TOKEN)
    
    try:
        print("🔍 Testing bot authentication...")
        auth_result = client.auth_test()
        print(f"✅ Auth successful: {auth_result}")
        
        # Try to get bot info
        bot_info = client.bots_info(bot=auth_result['user_id'])
        print(f"🤖 Bot info: {bot_info}")
        
    except SlackApiError as e:
        print(f"❌ Auth failed: {e.response}")
    except Exception as e:
        print(f"❌ Auth error: {str(e)}")

if __name__ == "__main__":
    print("🧪 Starting Slack Canvas API Test")
    print("=" * 50)
    
    test_bot_auth()
    print()
    test_canvas_creation()