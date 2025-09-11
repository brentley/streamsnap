# StreamSnap Technical Notes

## Canvas Integration Issues & Solutions

### Canvas Creation Bug (2025-09-10) - RESOLVED ✅
- **Issue**: Canvas API test shows success but main app fails with `canvas_creation_failed`
- **Resolution**: Canvas creation now works successfully! Debug logs show `✅ Successfully created Slack Canvas: F09EN6YDVFG`
- **New Issue**: Canvas ID mismatch between logs (F09EN6YDVFG) and Slack message (F09EN6Z70NS)
- **Status**: Canvas appears in channel attachments but still getting fallback Slack message

### Canvas URL Format
- **Correct Format**: `https://WORKSPACE.slack.com/docs/TEAM_ID/CANVAS_ID`
- **Example**: `https://vq8.slack.com/docs/T02L2C5BJ/F09FF2CHH88`
- **Team ID**: `T02L2C5BJ` (from auth.test)
- **Workspace**: `vq8` (extracted from auth.test URL)

### Canvas Title Duplication Fix
- **Issue**: Title appeared twice - once from Canvas API `title` parameter, once from `# title` in content
- **Solution**: Removed `# title` from content since Canvas API sets title separately

## Timestamp Accuracy Issues

### Root Cause: Timing Data is Available but Discarded
- **VTT Format**: YouTube provides WebVTT files with precise timing: `00:01:30.000 --> 00:01:35.000`
- **Current Issue**: We intentionally strip out `-->` lines containing timing data
- **Code Location**: Line ~608 in `extract_subtitle_text()`: `not '-->' in line`
- **Impact**: AI must guess timestamps instead of using actual timing data

### VTT Format Structure
```
WEBVTT

00:00:00.000 --> 00:00:03.000
I still think middle management's going

00:00:03.000 --> 00:00:06.000
to be hit really hard by AI
```

### Solution Required
1. Parse VTT timing data instead of discarding it
2. Create timed transcript segments 
3. Pass timing information to AI for accurate timestamp generation
4. Maintain text+timing pairs for precise topic boundaries

## Slack Bot Configuration

### Required Scopes
- `chat:write` ✅
- `canvases:write` ✅ 
- `channels:history` ✅
- `channels:read` ✅
- `im:history` ✅
- `app_mentions:read` ✅
- `users:read` ❌ (missing, causes bot_info failures)

### Channel Configuration
- **Test Channel ID**: `C09EMS0GXDG`
- **Bot Token**: `xoxb-2682413392-9483638786455-*`
- **Signing Secret**: `e661bd43655d8b4da2a324966ae8685f`

## AI Processing Pipeline

### Current Flow
1. **Video Info**: Extract title, duration from YouTube
2. **Transcript**: Download VTT but strip timing → plain text
3. **Summary**: Process text with Azure OpenAI
4. **Timestamps**: AI guesses timestamps from text content
5. **Canvas**: Create with title + summary + timestamps

### YouTube Chapters Discovery (2025-09-10) ✅
- **Major Finding**: YouTube videos often have accurate chapter data via yt-dlp
- **Example**: Nano Banana chapter starts at 28:33 (YouTube) vs 39:19 (AI guess) - 10+ min difference!
- **Chapter Data Available**: 13 chapters found for test video with precise titles and timestamps
- **Implementation**: Use `info.get('chapters', [])` from yt-dlp extract_info
- **Priority**: YouTube chapters >> VTT timing >> AI guessing

### Timing Data Pipeline (Updated)
1. **Video Info**: Extract title, duration, **chapters**
2. **Primary**: Use YouTube chapters if available (most accurate)
3. **Fallback**: Parse VTT timing for videos without chapters  
4. **Summary**: Process with chapter/timing context
5. **Timestamps**: Use chapter data or VTT timing
6. **Canvas**: Create with precise timing data

## Canvas Content Issues Fixed

### Notification Message Removal
- **Issue**: User wanted only Canvas in channel, not separate notification
- **Solution**: Removed `post_canvas_notification()` call when Canvas succeeds
- **Result**: Only Canvas document appears, no extra messages

### Full Transcript Section Removal
- **Issue**: Canvas too verbose with full transcript
- **Solution**: Removed transcript section from Canvas content
- **Content**: Now shows Duration + Video + Summary + Timestamps only

## Implementation Errors Found

### Variable Scoping Error (2025-09-10)
- **Error**: `NameError: name 'response' is not defined` at line 1780
- **Location**: `process_video_for_slack()` function in timestamp generation 
- **Issue**: Used `response['video_info']` instead of `video_info` in chapter extraction
- **Good News**: Chapters ARE being detected (logs show "Found 13 chapters")
- **VTT Timing**: New timing extraction working (preview shows "[00:00:00.080] content")
- **Fix Needed**: Change `response['video_info'].get('chapters', [])` to `video_info.get('chapters', [])`

### Successful Features (2025-09-10) ✅
- **Chapter Detection**: `📑 Found 13 chapters: ['Intro', 'AI Labor Market Signals', 'AI Industry's Increasing Political Influence']...`
- **VTT Timing**: `[00:00:00.080] content` format working
- **Transcript Size**: Increased from 232,180 to 325,662 chars (timing data included)
- **Canvas Link Only**: Removed fallback "Video Analysis Complete" messages when Canvas succeeds
- **Simple Workflow**: Canvas creation + simple URL posting, no verbose notifications

### Duplicate Canvas Creation Issue (2025-09-10) - RESOLVED ✅
- **Issue**: User reported seeing two Canvas URLs (F09E86MJ5RV and F09ESHSFEBE) for single video
- **Root Cause**: Canvas creation logic existed in TWO separate functions:
  1. `process_video_for_slack()` - Created Canvas when `auto_process_urls=true`
  2. `process_video_async()` - Created Canvas in background Slack processing
- **Resolution**: Removed duplicate Canvas creation from `process_video_for_slack()` at lines 1603-1617
- **Result**: Now only creates ONE Canvas per video in `process_video_async()` for Slack integration

### Link Shared Event Optimization (2025-09-10) - IMPLEMENTED ✅
- **Issue**: Bot was receiving webhook calls for every single message in Slack channels
- **Solution**: Switched from `message.channels` event to `link_shared` event subscription
- **Benefits**: 
  - Slack only sends webhooks when actual links are posted (much more efficient)
  - Reduces server load and bandwidth usage significantly
  - Still catches all YouTube URL formats including youtu.be short links
- **Implementation**: Added `link_shared` event handler in webhook at lines 2127-2174
- **Domains Configured**: youtube.com, youtu.be, www.youtube.com, m.youtube.com

### Duplicate Processing Prevention (2025-09-10) - IMPLEMENTED ✅
- **Issue**: Multiple `link_shared` events causing duplicate Canvas creation for same video
- **Root Cause**: Slack sends multiple webhook calls for same URL during unfurling process
- **Solution**: Added URL deduplication tracking with 10-minute window
- **Implementation**: 
  - Global `processing_urls` dictionary tracks active processing
  - Prevents duplicate processing within 10 minutes
  - Automatic cleanup after processing completes
  - Added at lines 22-24 (global variable) and 1951-1964 (deduplication logic)
- **Result**: Only one Canvas created per unique video URL, regardless of multiple webhook events

### Videos Without Chapters Error Fix (2025-09-10) - RESOLVED ✅
- **Issue**: `TypeError: object of type 'NoneType' has no len()` when processing videos without chapters
- **Error Location**: Line 435 in `get_video_info()` function when calling `len(chapters)`
- **Root Cause**: Some videos return `None` for chapters instead of empty list `[]`
- **Resolution**: Added null check at lines 435-436: `if chapters is None: chapters = []`
- **Result**: Videos without chapters now process correctly without errors

### Whisper API Timestamp Integration (2025-09-10) - IMPLEMENTED ✅
- **Feature**: Added OpenAI Whisper API integration for accurate timestamp generation
- **Implementation**: Two new functions in `streamsnap_app.py`:
  1. `transcribe_audio_with_whisper_timestamps()` (lines 822-909) - Downloads audio and transcribes with Azure OpenAI Whisper
  2. `generate_timestamps_from_whisper()` (lines 911-984) - Uses Whisper segments for AI topic boundary analysis
- **Integration**: Updated timestamp generation logic in both processing pipelines
- **Priority Order**: YouTube Chapters > Whisper Timestamps > AI Text Analysis
- **Benefits**:
  - Provides precise segment-level timestamps (~1-second accuracy)
  - More accurate topic boundaries than text-only AI analysis
  - Graceful fallback system maintains reliability
- **Status**: Successfully integrated and deployed

## Future Improvements Needed

1. **Queue System**: Prevent API overload when multiple URLs posted
2. **Error Handling**: Better fallback when Canvas creation fails