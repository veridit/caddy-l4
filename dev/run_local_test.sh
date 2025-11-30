#!/bin/bash

set -e  # Exit on error

echo "========================================="
echo "Caddy L4 Local Test Script"
echo "========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[STATUS]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to cleanup on exit
cleanup() {
    print_status "Cleaning up..."

    # Stop Caddy if it's running
    if [ -f caddy.pid ]; then
        PID=$(cat caddy.pid)
        if ps -p $PID > /dev/null 2>&1; then
            print_status "Stopping Caddy (PID: $PID)..."
            kill $PID 2>/dev/null || true
            rm -f caddy.pid
        fi
    fi

    print_status "Cleanup complete"
}

# Set up trap to cleanup on script exit
trap cleanup EXIT INT TERM

# Step 1: Check prerequisites
print_status "Checking prerequisites..."

if ! command -v xcaddy &> /dev/null; then
    print_error "xcaddy not found. Please install it first:"
    echo "  go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest"
    exit 1
fi

if ! command -v psql &> /dev/null; then
    print_error "psql not found. Please install PostgreSQL client tools."
    exit 1
fi

# Check if PostgreSQL is running on localhost:5432
if ! pg_isready -h localhost -p 5432 -q 2>/dev/null; then
    print_error "PostgreSQL is not running on localhost:5432"
    exit 1
fi

print_success "Prerequisites check passed"

# Step 2: Set up test database
print_status "Setting up test database..."

# Change to parent directory for database setup
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/.."

if psql -h localhost -U $USER -d postgres -f dev/setup_test_db.sql > /dev/null 2>&1; then
    print_success "Test database created"
else
    print_warning "Database setup may have failed, but continuing..."
fi

# Step 3: Build Caddy with caddy-l4
print_status "Building Caddy with caddy-l4..."

if xcaddy build --with github.com/mholt/caddy-l4=. > /dev/null 2>&1; then
    print_success "Caddy built successfully"
else
    print_error "Failed to build Caddy"
    exit 1
fi

# Step 4: Start Caddy
print_status "Starting Caddy with test configuration..."

# Start Caddy in background and save PID
./caddy run --config dev/test.caddyfile > caddy.log 2>&1 &
CADDY_PID=$!
echo $CADDY_PID > caddy.pid

# Wait for Caddy to start
sleep 3

if ! ps -p $CADDY_PID > /dev/null 2>&1; then
    print_error "Caddy failed to start"
    exit 1
fi

print_success "Caddy started (PID: $CADDY_PID)"

# Wait a bit more for ports to be bound
sleep 2

# Step 5: Run tests
print_status "Running tests..."
echo ""

TESTS_PASSED=0
TESTS_FAILED=0

# Test 1: Cleartext connection on port 15433
echo "========================================="
print_status "Test 1: Cleartext PostgreSQL (port 15433)"
if PGHOST=localhost PGPORT=15433 PGUSER=caddy_test PGPASSWORD=test_password_123 psql -d caddy_test -c 'SELECT 1 as test;' -t 2>/dev/null | grep -q "1"; then
    print_success "Test 1 PASSED: Cleartext connection works"
    ((TESTS_PASSED++))
else
    print_error "Test 1 FAILED: Cleartext connection failed"
    ((TESTS_FAILED++))
fi
echo ""

# Test 2: TLS connection with internal cert on port 15432
echo "========================================="
print_status "Test 2: TLS PostgreSQL with internal cert (port 15432)"
if PGSSLMODE=require PGHOST=localhost PGPORT=15432 PGUSER=caddy_test PGPASSWORD=test_password_123 psql -d caddy_test -c 'SELECT 1 as test;' -t 2>/dev/null | grep -q "1"; then
    print_success "Test 2 PASSED: TLS connection with internal cert works"
    ((TESTS_PASSED++))
else
    print_error "Test 2 FAILED: TLS connection failed"
    print_warning "This might be expected if internal cert is not trusted"
    ((TESTS_FAILED++))
fi
echo ""

# Test 3: TLS connection with explicit connection_policy on port 15434
echo "========================================="
print_status "Test 3: TLS PostgreSQL with connection_policy (port 15434)"
if PGSSLMODE=require PGHOST=localhost PGPORT=15434 PGUSER=caddy_test PGPASSWORD=test_password_123 psql -d caddy_test -c 'SELECT 1 as test;' -t 2>/dev/null | grep -q "1"; then
    print_success "Test 3 PASSED: TLS connection with connection_policy works"
    ((TESTS_PASSED++))
else
    print_error "Test 3 FAILED: TLS connection with connection_policy failed"
    ((TESTS_FAILED++))
fi
echo ""

# Step 6: Check Caddy logs for errors
print_status "Checking Caddy logs..."
echo ""
echo "Recent Caddy logs (last 20 lines):"
echo "-----------------------------------"
if [ -f caddy.log ]; then
    tail -20 caddy.log
else
    print_warning "No caddy.log file found"
fi
echo ""

# Step 7: Summary
echo "========================================="
echo "Test Summary"
echo "========================================="
print_status "Tests Passed: ${GREEN}${TESTS_PASSED}${NC}"
print_status "Tests Failed: ${RED}${TESTS_FAILED}${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    print_success "All tests passed!"
    exit 0
else
    print_error "Some tests failed"
    exit 1
fi
