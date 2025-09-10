<h1 align="center">
  <br>
  🎯 StreamSnap
  <br>
</h1>

<h4 align="center">AI-Powered YouTube Video Summarizer with Smart Transcripts</h4>

<p align="center">
  <a href="https://github.com/brentley/streamsnap/issues"><img src="https://img.shields.io/github/issues/brentley/streamsnap"></a> 
  <a href="https://github.com/brentley/streamsnap/stargazers"><img src="https://img.shields.io/github/stars/brentley/streamsnap"></a>
  <a href="https://github.com/brentley/streamsnap/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg">
  </a>
  <img src="https://img.shields.io/badge/Python-3.10+-brightgreen.svg">
  <img src="https://img.shields.io/badge/Azure-OpenAI-orange.svg">
</p>

<p align="center">
  <a href="#overview-">Overview</a> •
  <a href="#features-">Features</a> •
  <a href="#getting-started-">Getting Started</a> •
  <a href="#contributing">Contributing</a> 
</p>

<p align="center">
  <a href="https://github.com/siddharthsky/ai-video-summarizer-and-timestamp-generator-LLM-p"><img src="https://raw.githubusercontent.com/siddharthsky/google-gemini-yt-video-summarizer-AI-p/main/research/demo3.gif" alt="Usage Demo"></a>
</p>




## Overview 📝

**StreamSnap** is an intelligent YouTube video processing platform that automatically generates comprehensive analysis for any video. Built with Azure OpenAI and optimized for efficiency, StreamSnap automatically produces three essential outputs for every video: AI-powered summaries, clickable timestamps, and full transcripts.

🚀 **Key Innovation**: StreamSnap prioritizes YouTube's existing transcripts when available, only downloading and processing audio when necessary - making it faster and more efficient than traditional solutions.

## Features ✨

- **🎯 Automatic Triple Output**: Every video automatically generates summary, timestamps, AND transcript
- **⚡ Smart Transcript Detection**: Prioritizes YouTube transcripts, only downloads when needed  
- **🤖 Azure OpenAI Integration**: Advanced AI processing with configurable models
- **📱 Modern Web Interface**: Responsive design with tabbed results and PWA support
- **🔧 Comprehensive Configuration**: 43+ configurable settings via admin panel
- **🔗 Slack Integration**: Automated processing with rich document responses
- **📊 Admin Dashboard**: Real-time settings management with environment overrides
- **🐳 Docker Ready**: Full containerization with CI/CD workflows

## Getting Started 🚀

### Prerequisites

- Python 3.10
- LLM Model API Keys [[🔑]](https://github.com/siddharthsky/ai-video-summarizer-and-timestamp-generator-LLM-p/tree/main?tab=readme-ov-file#get-api-keys)

### Usage

1. Clone the repository:
```
git clone https://github.com/siddharthsky/ai-video-summarizer-and-timestamp-generator-LLM-p.git
```
2. Navigate to the project directory:
```
cd ai-video-summarizer-and-timestamp-generator-LLM-p
```
3. Install dependencies:
```
pip install -r requirements.txt
```
4. Create a ".env" file ⬇️ [add whichever is available]
```
GOOGLE_GEMINI_API_KEY = "Your-Gemini-Key-Here"
OPENAI_CHATGPT_API_KEY = "Your-Openai-Key-Here"
```

### Get API Keys:

- [Google Gemini API key](https://makersuite.google.com/app/apikey) 🔑 
   
- [OpenAI ChatGPT API key](https://platform.openai.com/signup) 🔑 
   

5 Run the summarizer:
```
streamlit run app.py
```


## Contributing

Contributions are welcome from the community!, Whether it's feedback, suggestions, or code improvements, your input is valuable. 

## Acknowledgments

- [Google Gemini](https://ai.google.dev/)
- [OpenAI ChatGPT](https://help.openai.com/en/) 
- [Krish Naik](https://www.youtube.com/user/krishnaik06) 
