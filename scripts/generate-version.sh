#!/bin/bash

# Generate version information for build
echo "Generating version information..."

# Get git information
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION=${VERSION:-"1.0.0"}
ENVIRONMENT=${ENVIRONMENT:-"production"}

# Create version file
cat > version_build.json << EOF
{
  "version": "${VERSION}",
  "commit": "${GIT_COMMIT}",
  "branch": "${GIT_BRANCH}",
  "build_date": "${BUILD_DATE}",
  "environment": "${ENVIRONMENT}"
}
EOF

echo "Generated version info:"
cat version_build.json