#!/bin/bash

# SlowHTTP v2 - Installation Test Script
# Version: 5.0
# This script tests if all components are properly installed

echo "=========================================="
echo "SlowHTTP v2 - Installation Test"
echo "Version: 5.0"
echo "=========================================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
PASSED=0
FAILED=0

# Function to test command
test_command() {
    if command -v $1 &> /dev/null; then
        echo -e "${GREEN}✓${NC} $1 is installed"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗${NC} $1 is NOT installed"
        ((FAILED++))
        return 1
    fi
}

# Function to test Python module
test_python_module() {
    if python3 -c "import $1" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Python module '$1' is installed"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗${NC} Python module '$1' is NOT installed"
        ((FAILED++))
        return 1
    fi
}

# Function to test file
test_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}✓${NC} File '$1' exists"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗${NC} File '$1' does NOT exist"
        ((FAILED++))
        return 1
    fi
}

echo "1. Testing System Commands..."
echo "------------------------------"
test_command python3
test_command pip3
test_command git
echo ""

echo "2. Testing Python Version..."
echo "----------------------------"
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" = "$REQUIRED_VERSION" ]; then
    echo -e "${GREEN}✓${NC} Python version $PYTHON_VERSION (>= $REQUIRED_VERSION required)"
    ((PASSED++))
else
    echo -e "${RED}✗${NC} Python version $PYTHON_VERSION (>= $REQUIRED_VERSION required)"
    ((FAILED++))
fi
echo ""

echo "3. Testing Python Modules..."
echo "----------------------------"
test_python_module paramiko
test_python_module cryptography
test_python_module colorama
test_python_module psutil
test_python_module requests
test_python_module dns.resolver
echo ""

echo "4. Testing Application Files..."
echo "-------------------------------"
test_file slowhttpv2.py
test_file agent_upgraded.py
test_file database_manager_upgraded.py
test_file ssh_manager_upgraded.py
test_file default_config.py
echo ""

echo "5. Testing Documentation Files..."
echo "---------------------------------"
test_file README.md
test_file INSTALLATION.md
test_file CHANGELOG.md
test_file requirements.txt
test_file UPGRADE_SUMMARY.md
echo ""

echo "6. Testing Application Syntax..."
echo "--------------------------------"
if python3 -m py_compile slowhttpv2.py 2>/dev/null; then
    echo -e "${GREEN}✓${NC} slowhttpv2.py syntax is valid"
    ((PASSED++))
else
    echo -e "${RED}✗${NC} slowhttpv2.py has syntax errors"
    ((FAILED++))
fi

if python3 -m py_compile agent_upgraded.py 2>/dev/null; then
    echo -e "${GREEN}✓${NC} agent_upgraded.py syntax is valid"
    ((PASSED++))
else
    echo -e "${RED}✗${NC} agent_upgraded.py has syntax errors"
    ((FAILED++))
fi
echo ""

echo "7. Testing Version Constants..."
echo "-------------------------------"
if grep -q "VERSION = &quot;5.0&quot;" slowhttpv2.py; then
    echo -e "${GREEN}✓${NC} slowhttpv2.py has correct VERSION"
    ((PASSED++))
else
    echo -e "${RED}✗${NC} slowhttpv2.py VERSION is incorrect"
    ((FAILED++))
fi

if grep -q "VERSION = &quot;5.0&quot;" agent_upgraded.py; then
    echo -e "${GREEN}✓${NC} agent_upgraded.py has correct VERSION"
    ((PASSED++))
else
    echo -e "${RED}✗${NC} agent_upgraded.py VERSION is incorrect"
    ((FAILED++))
fi
echo ""

echo "8. Testing Directory Structure..."
echo "---------------------------------"
if [ -d "logs" ] || mkdir -p logs 2>/dev/null; then
    echo -e "${GREEN}✓${NC} logs directory exists/created"
    ((PASSED++))
else
    echo -e "${RED}✗${NC} Cannot create logs directory"
    ((FAILED++))
fi
echo ""

# Summary
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo "Total: $((PASSED + FAILED))"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed! Installation is complete.${NC}"
    echo ""
    echo "You can now run the application:"
    echo "  python3 slowhttpv2.py"
    echo ""
    exit 0
else
    echo -e "${RED}✗ Some tests failed. Please fix the issues above.${NC}"
    echo ""
    echo "To install missing dependencies:"
    echo "  pip3 install -r requirements.txt"
    echo ""
    exit 1
fi
