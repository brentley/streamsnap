#!/bin/bash

# StreamSnap Safe Restart Script
# This script safely restarts StreamSnap containers, waiting for active processing to complete

set -e

# Configuration
CONTAINER_NAME="streamsnap"
API_BASE_URL="http://localhost:5000"
MAX_WAIT_TIME=300  # 5 minutes
CHECK_INTERVAL=5   # 5 seconds
TIMEOUT_FORCE=600  # 10 minutes total timeout

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

# Function to check if container is running
is_container_running() {
    docker ps --filter "name=${CONTAINER_NAME}" --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"
}

# Function to check system status via API
check_system_status() {
    local response
    response=$(curl -s -f "${API_BASE_URL}/api/system/status" 2>/dev/null) || return 1
    echo "$response"
}

# Function to request graceful shutdown via API
request_graceful_shutdown() {
    local response
    response=$(curl -s -f -X POST "${API_BASE_URL}/api/system/safe-restart" 2>/dev/null) || return 1
    echo "$response"
}

# Function to cancel graceful shutdown
cancel_graceful_shutdown() {
    local response
    response=$(curl -s -f -X POST "${API_BASE_URL}/api/system/cancel-restart" 2>/dev/null) || return 1
    echo "$response"
}

# Function to wait for safe restart
wait_for_safe_restart() {
    local start_time=$(date +%s)
    local current_time
    local elapsed
    
    log "⏳ Waiting for active processing to complete..."
    
    while true; do
        current_time=$(date +%s)
        elapsed=$((current_time - start_time))
        
        if [ $elapsed -gt $MAX_WAIT_TIME ]; then
            log_warning "⚠️  Timeout after ${MAX_WAIT_TIME}s waiting for graceful shutdown"
            return 1
        fi
        
        local status_response
        status_response=$(check_system_status)
        
        if [ $? -eq 0 ]; then
            local can_restart=$(echo "$status_response" | jq -r '.can_safely_restart // false')
            local active_count=$(echo "$status_response" | jq -r '.active_count // 0')
            
            if [ "$can_restart" = "true" ]; then
                log_success "✅ All processing complete - safe to restart (${elapsed}s elapsed)"
                return 0
            else
                log "⏳ Still waiting... ${active_count} active threads (${elapsed}s elapsed)"
            fi
        else
            log_warning "⚠️  Cannot reach API - container may already be down"
            return 0  # Assume safe if we can't reach API
        fi
        
        sleep $CHECK_INTERVAL
    done
}

# Function to wait for container health
wait_for_healthy_container() {
    local start_time=$(date +%s)
    local current_time
    local elapsed
    
    log "⏳ Waiting for container to be healthy..."
    
    while true; do
        current_time=$(date +%s)
        elapsed=$((current_time - start_time))
        
        if [ $elapsed -gt $TIMEOUT_FORCE ]; then
            log_error "❌ Timeout waiting for container to be healthy"
            return 1
        fi
        
        if is_container_running; then
            # Check if API responds
            if check_system_status > /dev/null 2>&1; then
                log_success "✅ Container is healthy and API is responding (${elapsed}s elapsed)"
                return 0
            else
                log "⏳ Container running but API not ready yet (${elapsed}s elapsed)"
            fi
        else
            log "⏳ Container not ready yet (${elapsed}s elapsed)"
        fi
        
        sleep $CHECK_INTERVAL
    done
}

# Function to perform restart operation
perform_restart() {
    local operation="$1"  # "restart" or "rebuild"
    
    log "🔄 Performing container ${operation}..."
    
    if [ "$operation" = "rebuild" ]; then
        log "🏗️  Rebuilding container with latest code..."
        docker compose down
        git pull origin main
        docker compose up -d --build
    else
        log "🔄 Restarting container..."
        docker compose restart "${CONTAINER_NAME}"
    fi
    
    if [ $? -eq 0 ]; then
        log_success "✅ Container ${operation} command completed"
        return 0
    else
        log_error "❌ Container ${operation} failed"
        return 1
    fi
}

# Main function
main() {
    local operation="${1:-restart}"  # Default to restart if no argument
    
    log "🚀 Starting StreamSnap safe ${operation}..."
    
    # Check if jq is available
    if ! command -v jq &> /dev/null; then
        log_error "❌ jq is required but not installed. Please install jq first."
        exit 1
    fi
    
    # Check if container is running
    if ! is_container_running; then
        log_error "❌ Container '${CONTAINER_NAME}' is not running"
        exit 1
    fi
    
    # Step 1: Check current system status
    log "📊 Step 1: Checking system status..."
    local initial_status
    initial_status=$(check_system_status)
    
    if [ $? -ne 0 ]; then
        log_error "❌ Cannot reach StreamSnap API at ${API_BASE_URL}"
        log_error "   Make sure the container is running and accessible"
        exit 1
    fi
    
    local can_restart=$(echo "$initial_status" | jq -r '.can_safely_restart // false')
    local active_count=$(echo "$initial_status" | jq -r '.active_count // 0')
    
    log "   Active threads: ${active_count}"
    log "   Can safely restart: ${can_restart}"
    
    # Step 2: If not safe, request graceful shutdown
    if [ "$can_restart" != "true" ]; then
        log "🛑 Step 2: Requesting graceful shutdown..."
        local shutdown_response
        shutdown_response=$(request_graceful_shutdown)
        
        if [ $? -ne 0 ]; then
            log_error "❌ Failed to request graceful shutdown"
            exit 1
        fi
        
        log_success "✅ Graceful shutdown requested"
        
        # Step 3: Wait for safe restart
        log "⏳ Step 3: Waiting for active processing to complete..."
        if ! wait_for_safe_restart; then
            log_error "❌ Timeout waiting for graceful shutdown"
            log_error "   You can force restart with: docker compose restart ${CONTAINER_NAME}"
            log_error "   Or wait longer and try again"
            exit 1
        fi
    else
        log_success "✅ System is already idle - safe to restart immediately"
    fi
    
    # Step 4: Perform restart/rebuild
    log "🔄 Step 4: Performing ${operation}..."
    if ! perform_restart "$operation"; then
        log_error "❌ ${operation^} failed"
        exit 1
    fi
    
    # Step 5: Wait for container to be healthy
    log "⏳ Step 5: Waiting for container to be healthy..."
    if ! wait_for_healthy_container; then
        log_error "❌ Container did not become healthy within timeout"
        log_error "   Check logs with: docker compose logs ${CONTAINER_NAME}"
        exit 1
    fi
    
    # Step 6: Verify system is working
    log "🔍 Step 6: Verifying system status..."
    local final_status
    final_status=$(check_system_status)
    
    if [ $? -eq 0 ]; then
        log_success "✅ StreamSnap ${operation} completed successfully!"
        log_success "   System is ready to process YouTube videos"
        log_success "   Dashboard: ${API_BASE_URL}/dashboard"
    else
        log_warning "⚠️  Container is running but API may not be fully ready yet"
        log_warning "   Check logs if issues persist: docker compose logs ${CONTAINER_NAME}"
    fi
}

# Handle script arguments
case "${1:-}" in
    restart)
        main "restart"
        ;;
    rebuild)
        main "rebuild"
        ;;
    status)
        log "📊 Checking StreamSnap status..."
        status_response=$(check_system_status)
        if [ $? -eq 0 ]; then
            echo "$status_response" | jq '.'
        else
            log_error "❌ Cannot reach StreamSnap API"
            exit 1
        fi
        ;;
    cancel)
        log "❌ Cancelling graceful shutdown..."
        cancel_response=$(cancel_graceful_shutdown)
        if [ $? -eq 0 ]; then
            log_success "✅ Graceful shutdown cancelled"
        else
            log_error "❌ Failed to cancel graceful shutdown"
            exit 1
        fi
        ;;
    help|--help|-h)
        echo "StreamSnap Safe Restart Script"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  restart   - Safely restart the container (default)"
        echo "  rebuild   - Pull latest code and rebuild container" 
        echo "  status    - Check current system status"
        echo "  cancel    - Cancel graceful shutdown request"
        echo "  help      - Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0 restart   # Safe restart"
        echo "  $0 rebuild   # Pull code and rebuild"
        echo "  $0 status    # Check status"
        echo ""
        ;;
    *)
        log_error "❌ Unknown command: ${1:-}"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac