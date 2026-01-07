#!/bin/bash

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

# Function to generate random password
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-32
}

# Set script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Check if .env exists, if not create it
if [ ! -f "$SCRIPT_DIR/.env" ]; then
    print_status "No .env file found, generating one..."
    
    # Generate random password
    GENERATED_PASSWORD=$(generate_password)
    
    # Create .env file
    cat > "$SCRIPT_DIR/.env" << EOF
# PostgreSQL test configuration
# Auto-generated on $(date)

# PostgreSQL test user
PGUSER=caddy_test

# PostgreSQL test password (auto-generated)
PGPASSWORD=$GENERATED_PASSWORD

# PostgreSQL test database
PGDATABASE=caddy_test
EOF
    
    print_success "Generated .env file with random password"
fi

# Load environment variables from .env
if [ -f "$SCRIPT_DIR/.env" ]; then
    print_status "Loading configuration from .env"
    export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
else
    print_error ".env file not found"
    exit 1
fi

# Function to cleanup on exit
cleanup() {
    print_status "Cleaning up..."

    # Stop Caddy if it's running
    if [ -f dev/build/caddy.pid ]; then
        PID=$(cat dev/build/caddy.pid)
        if ps -p $PID > /dev/null 2>&1; then
            print_status "Stopping Caddy (PID: $PID)..."
            kill $PID 2>/dev/null || true
            rm -f dev/build/caddy.pid
        fi
    fi

    print_status "Cleanup complete"
}

# Set up trap to cleanup on script exit
trap cleanup EXIT INT TERM

# Check debug mode
if [ "${DEBUG}" = "1" ]; then
    print_status "Debug mode enabled"
    OUTPUT_REDIRECT="/dev/stdout"
    PSQL_OUTPUT="/dev/stdout"
    PSQL_STDERR="2>&1"
else
    OUTPUT_REDIRECT="/dev/null"
    PSQL_OUTPUT="/dev/null"
    PSQL_STDERR="2>/dev/null"
fi

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
cd "$SCRIPT_DIR/.."

# Export password for psql
export PGPASSWORD_ADMIN="${PGPASSWORD_ADMIN:-}"

if psql -h localhost -U $USER -d postgres \
    -v pg_user="$PGUSER" \
    -v pg_password="$PGPASSWORD" \
    -v pg_database="$PGDATABASE" \
    -f dev/setup_test_db.sql > $OUTPUT_REDIRECT 2>&1; then
    print_success "Test database created"
else
    print_error "Failed to set up test database"
    exit 1
fi

# Step 3: Build Caddy with caddy-l4
print_status "Building Caddy with caddy-l4..."

# Notice that while `xcaddy` runs the local version, `xcaddy build` does *not* include
# any modules of the directory you are in, to do that one must use the regular `--with`
# of xcaddy, and in addition, tell it to load that from the local directory.
if xcaddy build --with github.com/mholt/caddy-l4=. --output dev/build/caddy > $OUTPUT_REDIRECT 2>&1; then
    print_success "Caddy built successfully"
else
    print_error "Failed to build Caddy"
    exit 1
fi

# Step 4: Start Caddy
print_status "Starting Caddy with test configuration..."

# Start Caddy in background and save PID
./dev/build/caddy run --config dev/test.caddyfile --pidfile dev/build/caddy.pid > dev/build/caddy.log 2>&1 &

# Wait for Caddy to start
sleep 3

CADDY_PID=$(cat dev/build/caddy.pid)

if ! ps -p $CADDY_PID > /dev/null 2>&1; then
    print_error "Caddy failed to start"
    if [ -f dev/build/caddy.log ]; then
        echo "-----------------------------------"
        echo "Caddy Log Output:"
        cat dev/build/caddy.log
        echo "-----------------------------------"
    fi
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
if [ "${DEBUG}" = "1" ]; then
    print_status "Running: PGHOST=localhost PGPORT=15433 PGUSER=$PGUSER psql -d $PGDATABASE -c 'SELECT 1 as test;' -t"
    PGHOST=localhost PGPORT=15433 PGUSER=$PGUSER PGPASSWORD=$PGPASSWORD psql -d $PGDATABASE -c 'SELECT 1 as test;' -t 2>&1
    TEST_RESULT=$?
else
    PGHOST=localhost PGPORT=15433 PGUSER=$PGUSER PGPASSWORD=$PGPASSWORD psql -d $PGDATABASE -c 'SELECT 1 as test;' -t 2>/dev/null | grep -q "1"
    TEST_RESULT=$?
fi

if [ $TEST_RESULT -eq 0 ]; then
    print_success "Test 1 PASSED: Cleartext connection works"
    ((TESTS_PASSED++))
else
    print_error "Test 1 FAILED: Cleartext connection failed"
    ((TESTS_FAILED++))
fi
echo ""

# Test 2: TLS connection with internal cert on port 15432
echo "========================================="
print_status "Test 2: TLS PostgreSQL with internal cert (port 15432, PGSSLMODE=require - no cert verification)"
if [ "${DEBUG}" = "1" ]; then
    print_status "Running: PGSSLNEGOTIATION=direct PGSSLMODE=require PGSSLSNI=1 PGHOST=localhost PGPORT=15432 PGUSER=$PGUSER psql -d $PGDATABASE -c 'SELECT 1 as test;' -t"
    PGSSLNEGOTIATION=direct PGSSLMODE=require PGSSLSNI=1 PGHOST=localhost PGPORT=15432 PGUSER=$PGUSER PGPASSWORD=$PGPASSWORD psql -d $PGDATABASE -c 'SELECT 1 as test;' -t 2>&1
    TEST_RESULT=$?
else
    PGSSLNEGOTIATION=direct PGSSLMODE=require PGSSLSNI=1 PGHOST=localhost PGPORT=15432 PGUSER=$PGUSER PGPASSWORD=$PGPASSWORD psql -d $PGDATABASE -c 'SELECT 1 as test;' -t 2>/dev/null | grep -q "1"
    TEST_RESULT=$?
fi

if [ $TEST_RESULT -eq 0 ]; then
    print_success "Test 2 PASSED: TLS negotiation with internal cert works (no verification)"
    ((TESTS_PASSED++))
else
    print_error "Test 2 FAILED: TLS negotiation failed"
    ((TESTS_FAILED++))
fi
echo ""

# Test 3: TLS connection with explicit connection_policy on port 15434
echo "========================================="
print_status "Test 3: TLS PostgreSQL with connection_policy (port 15434)"
if [ "${DEBUG}" = "1" ]; then
    print_status "Running: PGSSLNEGOTIATION=direct PGSSLMODE=require PGSSLSNI=1 PGHOST=localhost PGPORT=15434 PGUSER=$PGUSER psql -d $PGDATABASE -c 'SELECT 1 as test;' -t"
    PGSSLNEGOTIATION=direct PGSSLMODE=require PGSSLSNI=1 PGHOST=localhost PGPORT=15434 PGUSER=$PGUSER PGPASSWORD=$PGPASSWORD psql -d $PGDATABASE -c 'SELECT 1 as test;' -t 2>&1
    TEST_RESULT=$?
else
    PGSSLNEGOTIATION=direct PGSSLMODE=require PGSSLSNI=1 PGHOST=localhost PGPORT=15434 PGUSER=$PGUSER PGPASSWORD=$PGPASSWORD psql -d $PGDATABASE -c 'SELECT 1 as test;' -t 2>/dev/null | grep -q "1"
    TEST_RESULT=$?
fi
if [ $TEST_RESULT -eq 0 ]; then
    print_success "Test 3 PASSED: TLS connection with connection_policy works"
    ((TESTS_PASSED++))
else
    print_error "Test 3 FAILED: TLS connection with connection_policy failed"
    ((TESTS_FAILED++))
fi
echo ""

# Test 4: TLS connection with SNI routing on port 15435
echo "========================================="
print_status "Test 4: TLS PostgreSQL with SNI routing (port 15435, local.statbus.org)"
if [ "${DEBUG}" = "1" ]; then
    print_status "Running: PGSSLNEGOTIATION=direct PGSSLMODE=require PGSSLSNI=1 PGHOST=local.statbus.org PGPORT=15435 PGUSER=$PGUSER psql -d $PGDATABASE -c 'SELECT 1 as test;' -t"
    PGSSLNEGOTIATION=direct PGSSLMODE=require PGSSLSNI=1 PGHOST=local.statbus.org PGPORT=15435 PGUSER=$PGUSER PGPASSWORD=$PGPASSWORD psql -d $PGDATABASE -c 'SELECT 1 as test;' -t 2>&1
    TEST_RESULT=$?
else
    PGSSLNEGOTIATION=direct PGSSLMODE=require PGSSLSNI=1 PGHOST=local.statbus.org PGPORT=15435 PGUSER=$PGUSER PGPASSWORD=$PGPASSWORD psql -d $PGDATABASE -c 'SELECT 1 as test;' -t 2>/dev/null | grep -q "1"
    TEST_RESULT=$?
fi
if [ $TEST_RESULT -eq 0 ]; then
    # Check if SNI was logged
    if grep -q '"server_name":"local\.statbus\.org"' dev/build/caddy.log; then
        print_success "Test 4 PASSED: SNI routing works and server_name logged"
        ((TESTS_PASSED++))
    else
        print_error "Test 4 FAILED: Connection succeeded but SNI not found in logs"
        ((TESTS_FAILED++))
    fi
else
    print_error "Test 4 FAILED: TLS connection with SNI routing failed"
    ((TESTS_FAILED++))
fi
echo ""

# Test 5: PostgreSQL over HTTPS port with listener_wrappers (port 9443)
echo "========================================="
print_status "Test 5: PostgreSQL over HTTPS port via listener_wrappers (port 9443, local.statbus.org)"
if [ "${DEBUG}" = "1" ]; then
    print_status "Running: PGSSLNEGOTIATION=direct PGSSLMODE=require PGSSLSNI=1 PGHOST=local.statbus.org PGPORT=9443 PGUSER=$PGUSER psql -d $PGDATABASE -c 'SELECT 1 as test;' -t"
    PGSSLNEGOTIATION=direct PGSSLMODE=require PGSSLSNI=1 PGHOST=local.statbus.org PGPORT=9443 PGUSER=$PGUSER PGPASSWORD=$PGPASSWORD psql -d $PGDATABASE -c 'SELECT 1 as test;' -t 2>&1
    TEST_RESULT=$?
else
    PGSSLNEGOTIATION=direct PGSSLMODE=require PGSSLSNI=1 PGHOST=local.statbus.org PGPORT=9443 PGUSER=$PGUSER PGPASSWORD=$PGPASSWORD psql -d $PGDATABASE -c 'SELECT 1 as test;' -t 2>/dev/null | grep -q "1"
    TEST_RESULT=$?
fi
if [ $TEST_RESULT -eq 0 ]; then
    # Check if postgres matcher was used in listener wrapper
    if grep -q 'layer4.matchers.postgres' dev/build/caddy.log && grep -q '"handling connection within listener wrapper"' dev/build/caddy.log; then
        print_success "Test 5 PASSED: PostgreSQL multiplexed on HTTPS port"
        ((TESTS_PASSED++))
    else
        print_error "Test 5 FAILED: Connection succeeded but listener_wrapper logs missing"
        ((TESTS_FAILED++))
    fi
else
    print_error "Test 5 FAILED: PostgreSQL connection over HTTPS port failed"
    ((TESTS_FAILED++))
fi
echo ""

# Test 6: Cleartext PostgreSQL over HTTP port (port 8080)
echo "========================================="
print_status "Test 6: Cleartext PostgreSQL over HTTP port via listener_wrappers (port 8080)"
if [ "${DEBUG}" = "1" ]; then
    print_status "Running: PGHOST=localhost PGPORT=8080 PGUSER=$PGUSER psql -d $PGDATABASE -c 'SELECT 1 as test;' -t"
    PGHOST=localhost PGPORT=8080 PGUSER=$PGUSER PGPASSWORD=$PGPASSWORD psql -d $PGDATABASE -c 'SELECT 1 as test;' -t 2>&1
    TEST_RESULT=$?
else
    PGHOST=localhost PGPORT=8080 PGUSER=$PGUSER PGPASSWORD=$PGPASSWORD psql -d $PGDATABASE -c 'SELECT 1 as test;' -t 2>/dev/null | grep -q "1"
    TEST_RESULT=$?
fi
if [ $TEST_RESULT -eq 0 ]; then
    print_success "Test 6 PASSED: Cleartext PostgreSQL over HTTP port works"
    ((TESTS_PASSED++))
else
    print_error "Test 6 FAILED: Cleartext PostgreSQL over HTTP port failed"
    ((TESTS_FAILED++))
fi
echo ""

# Test 7: Verify cleartext PostgreSQL does NOT work over HTTPS port (should fail)
echo "========================================="
print_status "Test 7: Verify cleartext PostgreSQL blocked on HTTPS port (should fail)"
if [ "${DEBUG}" = "1" ]; then
    print_status "Running: timeout 2 PGHOST=localhost PGPORT=9443 PGUSER=$PGUSER psql -d $PGDATABASE -c 'SELECT 1 as test;' -t (should fail)"
    timeout 2 bash -c "PGHOST=localhost PGPORT=9443 PGUSER=$PGUSER PGPASSWORD=$PGPASSWORD psql -d $PGDATABASE -c 'SELECT 1 as test;' -t 2>&1"
    TEST_RESULT=$?
else
    timeout 2 bash -c "PGHOST=localhost PGPORT=9443 PGUSER=$PGUSER PGPASSWORD=$PGPASSWORD psql -d $PGDATABASE -c 'SELECT 1 as test;' -t 2>/dev/null | grep -q '1'" 2>/dev/null
    TEST_RESULT=$?
fi
if [ $TEST_RESULT -ne 0 ]; then
    print_success "Test 7 PASSED: Cleartext PostgreSQL correctly blocked on HTTPS port"
    ((TESTS_PASSED++))
else
    print_error "Test 7 FAILED: Cleartext PostgreSQL should NOT work on HTTPS port"
    ((TESTS_FAILED++))
fi
echo ""

# Test 8: Verify cleartext PostgreSQL blocked on HTTP redirect port (should fail)
echo "========================================="
print_status "Test 8: Verify cleartext PostgreSQL blocked on HTTP redirect port 9080 (should fail)"
if [ "${DEBUG}" = "1" ]; then
    print_status "Running: timeout 2 PGHOST=localhost PGPORT=9080 PGUSER=$PGUSER psql -d $PGDATABASE -c 'SELECT 1 as test;' -t (should fail)"
    timeout 2 bash -c "PGHOST=localhost PGPORT=9080 PGUSER=$PGUSER PGPASSWORD=$PGPASSWORD psql -d $PGDATABASE -c 'SELECT 1 as test;' -t 2>&1"
    TEST_RESULT=$?
else
    timeout 2 bash -c "PGHOST=localhost PGPORT=9080 PGUSER=$PGUSER PGPASSWORD=$PGPASSWORD psql -d $PGDATABASE -c 'SELECT 1 as test;' -t 2>/dev/null | grep -q '1'" 2>/dev/null
    TEST_RESULT=$?
fi
if [ $TEST_RESULT -ne 0 ]; then
    print_success "Test 8 PASSED: Cleartext PostgreSQL correctly blocked on HTTP redirect port"
    ((TESTS_PASSED++))
else
    print_error "Test 8 FAILED: Cleartext PostgreSQL should NOT work on HTTP redirect port"
    ((TESTS_FAILED++))
fi
echo ""

# Step 6: Check Caddy logs for errors
print_status "Checking Caddy logs..."
echo ""
echo "Recent Caddy logs (last 20 lines):"
echo "-----------------------------------"
if [ -f dev/build/caddy.log ]; then
    tail -20 dev/build/caddy.log
else
    print_warning "No dev/build/caddy.log file found"
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
