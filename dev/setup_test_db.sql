-- Create test user for Caddy L4 testing
CREATE USER caddy_test WITH PASSWORD 'test_password_123';

-- Create test database
CREATE DATABASE caddy_test OWNER caddy_test;

-- Grant all privileges on the test database to the test user
GRANT ALL PRIVILEGES ON DATABASE caddy_test TO caddy_test;

-- Connect to the test database and set up a simple test table
\c caddy_test

-- Create a simple test table
CREATE TABLE IF NOT EXISTS test_table (
    id SERIAL PRIMARY KEY,
    message TEXT
);

-- Insert a test row
INSERT INTO test_table (message) VALUES ('Caddy L4 TLS test successful!');

-- Grant permissions on the table
GRANT ALL PRIVILEGES ON TABLE test_table TO caddy_test;
GRANT USAGE, SELECT ON SEQUENCE test_table_id_seq TO caddy_test;

-- Display confirmation
SELECT 'Test database and user created successfully!' as status;
