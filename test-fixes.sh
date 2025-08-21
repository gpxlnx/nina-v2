#!/bin/bash

# Test script for the fixes implemented in NINA Recon Optimized

echo "🧪 Testing NINA Recon Optimized fixes..."

# Test 1: Check if smart functions are available
echo -e "\n📋 Test 1: Smart functions availability"
source modules-optimized/core/config.sh

if type smart_save >/dev/null 2>&1; then
    echo "✅ smart_save function available"
else
    echo "❌ smart_save function not available"
fi

if type smart_combine >/dev/null 2>&1; then
    echo "✅ smart_combine function available"
else
    echo "❌ smart_combine function not available"
fi

if type file_has_content >/dev/null 2>&1; then
    echo "✅ file_has_content function available"
else
    echo "❌ file_has_content function not available"
fi

# Test 2: Test smart_save with empty content
echo -e "\n📋 Test 2: Smart file creation"
TEST_DIR="/tmp/nina-test"
mkdir -p "$TEST_DIR"

# Test empty content (should not create file)
if smart_save "$TEST_DIR/empty-test.txt" ""; then
    echo "❌ smart_save created file with empty content"
else
    echo "✅ smart_save correctly ignored empty content"
fi

# Test valid content (should create file)
if smart_save "$TEST_DIR/content-test.txt" "test content"; then
    echo "✅ smart_save created file with valid content"
else
    echo "❌ smart_save failed to create file with valid content"
fi

# Test 3: Check httpx module function
echo -e "\n📋 Test 3: HTTPX module functions"
if grep -q "run_httpx_module" nina-recon-optimized.sh; then
    echo "✅ run_httpx_module function found in main script"
else
    echo "❌ run_httpx_module function not found"
fi

# Test 4: Check vulnerabilities module fixes
echo -e "\n📋 Test 4: Vulnerabilities module"
if grep -q "file_has_content" modules-optimized/scanning/vulnerabilities.sh; then
    echo "✅ Vulnerabilities module uses smart functions"
else
    echo "❌ Vulnerabilities module not updated"
fi

if grep -q "smart_append" modules-optimized/scanning/vulnerabilities.sh; then
    echo "✅ Smart append functions implemented"
else
    echo "❌ Smart append functions not found"
fi

# Test 5: Basic syntax check
echo -e "\n📋 Test 5: Syntax checks"
for script in nina-recon-optimized.sh modules-optimized/*/*.sh; do
    if bash -n "$script" 2>/dev/null; then
        echo "✅ $(basename "$script") syntax OK"
    else
        echo "❌ $(basename "$script") syntax ERROR"
    fi
done

# Cleanup
rm -rf "$TEST_DIR"

echo -e "\n🎯 Test Summary Complete!"
