#!/bin/bash
# Deploy script for uploading updates to S3

if [ $# -eq 0 ]; then
    echo "Usage: ./deploy_update.sh <version>"
    exit 1
fi

VERSION=$1
S3_BASE="s3://arn:aws:s3:ap-southeast-2:917026075470:accesspoint/huginn-secure-updater"

echo "Deploying Huginn v$VERSION..."

# Upload release file
aws s3 cp "huginn_$VERSION.zip" "$S3_BASE/releases/"

# Upload manifest
aws s3 cp "manifest.json" "$S3_BASE/manifest/"

# Upload public key (if exists)
if [ -f "public.key" ]; then
    aws s3 cp "public.key" "$S3_BASE/"
fi

echo "Deployment complete!"