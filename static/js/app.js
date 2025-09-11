// StreamSnap JavaScript Application
class StreamSnapApp {
    constructor() {
        this.form = null;
        this.submitBtn = null;
        this.urlInput = null;
        this.isProcessing = false; // Prevent double requests
        this.init();
    }
    
    init() {
        console.log('StreamSnap initializing...');
        this.setupElements();
        this.setupEventListeners();
        console.log('StreamSnap ready!');
    }
    
    setupElements() {
        this.form = document.getElementById('video-form');
        this.submitBtn = document.querySelector('.submit-btn');
        this.urlInput = document.getElementById('youtube-url');
        this.pasteBtn = document.getElementById('paste-btn');
    }
    
    setupEventListeners() {
        if (this.form) {
            this.form.addEventListener('submit', (e) => this.handleFormSubmit(e));
        }
        
        if (this.pasteBtn) {
            this.pasteBtn.addEventListener('click', () => this.handlePasteClick());
        }
    }
    
    async handleFormSubmit(e) {
        e.preventDefault();
        
        // Prevent double requests
        if (this.isProcessing) {
            console.log('Already processing, ignoring duplicate request');
            return;
        }
        
        const url = this.urlInput.value.trim();
        if (!url) {
            this.showError('Please enter a YouTube URL');
            return;
        }
        
        console.log('Processing video:', url);
        this.isProcessing = true;
        this.setLoading(true);
        
        try {
            const response = await fetch('/api/process-all', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Processing failed');
            }
            
            if (data.success) {
                this.showVideoPreview(data.video_info);
                this.showAllResults(data.results, data.video_info.title);
                this.showSuccess('Video processed successfully!');
            } else {
                throw new Error(data.error || 'Unknown error');
            }
            
        } catch (error) {
            this.showError('Failed to process video: ' + error.message);
        } finally {
            this.setLoading(false);
            this.isProcessing = false;
        }
    }
    
    async handlePasteClick() {
        try {
            const text = await navigator.clipboard.readText();
            if (text && this.isYouTubeUrl(text)) {
                this.urlInput.value = text;
                this.urlInput.focus();
            } else {
                this.showError('Clipboard does not contain a valid YouTube URL');
            }
        } catch (error) {
            this.showError('Failed to read clipboard');
        }
    }
    
    isYouTubeUrl(url) {
        const patterns = [
            /youtube\.com\/watch\?v=/,
            /youtu\.be\//,
            /youtube\.com\/embed\//,
            /m\.youtube\.com\/watch\?v=/
        ];
        return patterns.some(pattern => pattern.test(url));
    }
    
    setLoading(loading) {
        if (this.submitBtn) {
            this.submitBtn.disabled = loading;
            const text = this.submitBtn.querySelector('.submit-text');
            if (text) {
                text.textContent = loading ? 'Processing...' : 'Process Video';
            }
        }
    }
    
    showError(message) {
        console.error('StreamSnap Error:', message);
        // Show error toast notification
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = message;
        errorDiv.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--error-color);
            color: white;
            padding: 1rem 2rem;
            border-radius: var(--border-radius);
            z-index: 9999;
            box-shadow: var(--shadow);
            max-width: 400px;
            word-wrap: break-word;
            animation: slideInFromRight 0.3s ease-out;
        `;
        document.body.appendChild(errorDiv);
        
        // Auto-remove after 8 seconds (longer for errors so user can read them)
        setTimeout(() => {
            if (errorDiv.parentNode) {
                errorDiv.remove();
            }
        }, 8000);
    }
    
    showSuccess(message) {
        console.log('StreamSnap Success:', message);
        // Show success message briefly
        const successDiv = document.createElement('div');
        successDiv.className = 'success-message';
        successDiv.textContent = message;
        successDiv.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--success-color);
            color: white;
            padding: 1rem 2rem;
            border-radius: var(--border-radius);
            z-index: 9999;
            box-shadow: var(--shadow);
        `;
        document.body.appendChild(successDiv);
        setTimeout(() => successDiv.remove(), 5000);
    }
    
    showVideoPreview(videoInfo) {
        const previewSection = document.getElementById('video-preview');
        const thumbnail = document.getElementById('video-thumbnail');
        const title = document.getElementById('video-title');
        const duration = document.getElementById('video-duration');
        const views = document.getElementById('video-views');
        
        if (thumbnail) thumbnail.src = videoInfo.thumbnail;
        if (title) title.textContent = videoInfo.title;
        if (duration) duration.textContent = videoInfo.duration;
        if (views) views.textContent = `${videoInfo.view_count.toLocaleString()} views`;
        
        if (previewSection) {
            previewSection.style.display = 'block';
            previewSection.scrollIntoView({ behavior: 'smooth' });
        }
    }
    
    showAllResults(results, videoTitle) {
        const resultsSection = document.getElementById('results-section');
        const resultsTitle = document.getElementById('results-title');
        
        // Set results title
        if (resultsTitle) resultsTitle.textContent = `Results: ${videoTitle}`;
        
        // Populate content areas
        this.populateContent('summary-content', results.summary);
        this.populateContent('timestamps-content', results.timestamps);
        this.populateContent('transcript-content', results.transcript);
        
        // Set up tab functionality
        this.setupResultsTabs();
        
        // Set up copy/download buttons
        this.setupActionButtons(results);
        
        // Show results section
        if (resultsSection) {
            resultsSection.style.display = 'block';
            resultsSection.scrollIntoView({ behavior: 'smooth' });
        }
    }
    
    populateContent(elementId, content) {
        const element = document.getElementById(elementId);
        if (element) {
            // Convert newlines to paragraphs for better formatting
            const paragraphs = content.split('\n\n').filter(p => p.trim());
            element.innerHTML = paragraphs.map(p => `<p>${p.trim()}</p>`).join('');
        }
    }
    
    setupResultsTabs() {
        const tabs = document.querySelectorAll('.results-tab');
        const panes = document.querySelectorAll('.tab-pane');
        
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                // Remove active class from all tabs and panes
                tabs.forEach(t => t.classList.remove('active'));
                panes.forEach(p => p.classList.remove('active'));
                
                // Add active class to clicked tab
                tab.classList.add('active');
                
                // Show corresponding pane
                const targetTab = tab.dataset.tab;
                const targetPane = document.getElementById(`${targetTab}-results`);
                if (targetPane) targetPane.classList.add('active');
            });
        });
    }
    
    setupActionButtons(results) {
        // Copy buttons
        document.querySelectorAll('.copy-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const type = btn.dataset.type;
                const content = results[type];
                navigator.clipboard.writeText(content).then(() => {
                    this.showSuccess(`${type.charAt(0).toUpperCase() + type.slice(1)} copied to clipboard!`);
                });
            });
        });
        
        // Download buttons
        document.querySelectorAll('.download-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const type = btn.dataset.type;
                const content = results[type];
                this.downloadAsFile(content, `streamsnap-${type}.txt`);
            });
        });
    }
    
    downloadAsFile(content, filename) {
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
}

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.StreamSnapApp = new StreamSnapApp();
});