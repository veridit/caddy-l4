-- Create test user for Caddy L4 testing
-- Variables are passed from psql command line using -v flag: pg_user, pg_password, pg_database

-- Create or update test user
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = :'pg_user') THEN
        EXECUTE format('CREATE USER %I WITH PASSWORD %L', :'pg_user', :'pg_password');
        RAISE NOTICE 'Created user: %', :'pg_user';
    ELSE
        EXECUTE format('ALTER USER %I WITH PASSWORD %L', :'pg_user', :'pg_password');
        RAISE NOTICE 'Updated password for user: %', :'pg_user';
    END IF;
END
$$;

-- Create test database if it doesn't exist
SELECT 'CREATE DATABASE ' || :'pg_database' || ' OWNER ' || :'pg_user'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'pg_database')\gexec

-- Grant all privileges on the test database to the test user
\set QUIET on
SELECT format('GRANT ALL PRIVILEGES ON DATABASE %I TO %I', :'pg_database', :'pg_user')\gexec
\set QUIET off

-- Connect to the test database
\c :pg_database

-- Create a simple test table
CREATE TABLE IF NOT EXISTS test_table (
    id SERIAL PRIMARY KEY,
    message TEXT
);

-- Insert a test row (skip if already exists)
INSERT INTO test_table (message) VALUES ('Caddy L4 TLS test successful!')
ON CONFLICT DO NOTHING;

-- Grant permissions on the table and sequence
\set QUIET on
SELECT format('GRANT ALL PRIVILEGES ON TABLE test_table TO %I', :'pg_user')\gexec
SELECT format('GRANT USAGE, SELECT ON SEQUENCE test_table_id_seq TO %I', :'pg_user')\gexec
\set QUIET off

-- Display confirmation
SELECT 'Test database and user created successfully!' as status;
