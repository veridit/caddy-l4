# Development Test Utilities

This directory contains utilities for local development and testing of caddy-l4.

## Files

### test.caddyfile

A simple test configuration for manually testing caddy-l4 functionality locally. This config sets up three layer4 servers:

- **Port 15432** - Route-level TLS with connection_policy (empty config for testing)
- **Port 15433** - Cleartext connections (no TLS)
- **Port 15434** - Route-level TLS with explicit connection_policy

All servers use the `echo` handler for simplicity.

### setup_test_db.sql

SQL script to create a test PostgreSQL database and user for integration testing.

**Usage:**
```bash
psql -h localhost -U postgres -f setup_test_db.sql
```

Creates:
- Database: `caddy_test`
- User: `caddy_test` with password `test_password_123`
- Test table with sample data

### run_local_test.sh

Automated test script that:
1. Checks prerequisites (xcaddy, psql, postgres running)
2. Sets up test database
3. Builds caddy with caddy-l4
4. Starts Caddy with test.caddyfile
5. Runs connection tests
6. Reports results and cleans up

**Usage:**
```bash
./run_local_test.sh
```

**Requirements:**
- PostgreSQL running on localhost:5432
- `xcaddy` installed
- `psql` client installed
- Admin access to PostgreSQL (for database creation)

## Quick Start

### Manual Testing

1. Start Caddy with the test config:
   ```bash
   xcaddy -- run --config dev/test.caddyfile
   ```

2. In another terminal, test connections:
   ```bash
   # Test cleartext (port 15433)
   echo "hello" | nc localhost 15433
   
   # Test TLS (port 15432 or 15434)
   echo "hello" | openssl s_client -connect localhost:15432 -quiet
   ```

3. Stop Caddy:
   ```bash
   # Press Ctrl+C in the Caddy terminal
   ```

### Automated Testing

Run the full test suite:
```bash
cd dev
./run_local_test.sh
```

The script will:
- ✅ Build caddy-l4
- ✅ Start Caddy
- ✅ Run tests
- ✅ Show results
- ✅ Clean up automatically

## Notes

- These utilities are for **development only**, not for production use
- The test configuration uses simple `echo` handlers, not actual PostgreSQL proxying
- Test database credentials are hardcoded - **do not use in production**
- Ports 15432-15434 are used to avoid conflicts with standard services
- The `xcaddy --` syntax is required to pass arguments to the locally built caddy

## Testing with Real PostgreSQL

To test with actual PostgreSQL connections instead of `echo`:

1. Make sure PostgreSQL is running on localhost:5432
2. Create test database: `psql -U postgres -f setup_test_db.sql`
3. Modify `test.caddyfile` to use `proxy localhost:5432` instead of `echo`
4. Test with psql:
   ```bash
   # Cleartext
   PGHOST=localhost PGPORT=15433 PGUSER=caddy_test PGPASSWORD=test_password_123 psql -d caddy_test -c 'SELECT 1;'
   
   # TLS
   PGSSLMODE=require PGHOST=localhost PGPORT=15432 PGUSER=caddy_test PGPASSWORD=test_password_123 psql -d caddy_test -c 'SELECT 1;'
   ```

## Troubleshooting

### "xcaddy not found"
Install xcaddy:
```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

### "PostgreSQL is not running"
Start PostgreSQL:
```bash
# macOS with Homebrew
brew services start postgresql

# Linux with systemd
sudo systemctl start postgresql
```

### "Port already in use"
Check what's using the ports:
```bash
lsof -i :15432
lsof -i :15433
lsof -i :15434
```

Kill the process or modify the ports in `test.caddyfile`.

## See Also

- [POSTGRES_TLS_EXAMPLE.md](../POSTGRES_TLS_EXAMPLE.md) - Production-ready configuration examples
- [integration/](../integration/) - Integration test suite