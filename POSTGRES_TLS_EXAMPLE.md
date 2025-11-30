# PostgreSQL with TLS in Caddy Layer4

This document provides working examples for configuring PostgreSQL with TLS termination in caddy-l4.

## Important: Server-Level vs Route-Level TLS

⚠️ **Server-level TLS shorthand is NOT supported** in layer4 servers:

```caddyfile
# ❌ THIS DOES NOT WORK
layer4 {
    :5432 {
        tls internal    # This is not supported
        route {
            proxy db:5432
        }
    }
}
```

✅ **Use route-level TLS handler with connection_policy blocks instead:**

```caddyfile
# ✅ THIS WORKS
layer4 {
    :5432 {
        route {
            tls {
                connection_policy {
                    # TLS configuration here
                }
            }
            proxy db:5432
        }
    }
}
```

## Working Examples

### Example 1: TLS-Only PostgreSQL (Simple)

All connections must use TLS. The simplest configuration:

```caddyfile
{
    debug
}

layer4 {
    :5432 {
        route {
            tls {
                connection_policy {
                    # Uses default certificate from global TLS app
                }
            }
            @postgres postgres
            route @postgres {
                proxy localhost:5432
            }
        }
    }
}
```

### Example 2: TLS-Only PostgreSQL with Internal Certificates

For local development, use an internal CA:

```caddyfile
{
    debug
    # Configure internal certificate authority
    pki {
        ca internal {
            name "Development CA"
        }
    }
}

# Create an HTTPS server to trigger cert generation
https://localhost {
    tls internal
    respond "OK"
}

# Layer4 server reuses the internal cert
layer4 {
    :5432 {
        route {
            tls {
                connection_policy {
                    # Will use the internal cert from above
                }
            }
            @postgres postgres
            route @postgres {
                proxy localhost:5432
            }
        }
    }
}
```

### Example 3: Cleartext-Only PostgreSQL

No TLS termination, just protocol matching and proxying:

```caddyfile
{
    debug
}

layer4 {
    :5432 {
        route {
            @postgres postgres
            route @postgres {
                proxy localhost:5432
            }
        }
    }
}
```

### Example 4: Multiplexing TLS and Cleartext (Advanced)

Accept both TLS and cleartext connections on the same port:

```caddyfile
{
    debug
}

layer4 {
    :5432 {
        # Route 1: Handle TLS connections
        @is_tls tls
        route @is_tls {
            tls {
                connection_policy {
                }
            }
            # After TLS termination, match on decrypted protocol
            subroute {
                @postgres postgres
                route @postgres {
                    proxy tls-backend:5432
                }
            }
        }
        
        # Route 2: Handle cleartext connections
        @postgres_cleartext postgres
        route @postgres_cleartext {
            proxy cleartext-backend:5432
        }
    }
}
```

**Important Notes:**
- The `tls` **matcher** detects TLS ClientHello (before termination)
- The `tls` **handler** terminates TLS (decrypts the connection)
- After termination, use `subroute` to match the decrypted protocol
- You cannot match raw TLS bytes against the `postgres` matcher simultaneously

### Example 5: Docker Compose Setup with Port Mapping

If you're using Docker Compose with port mapping like:
```yaml
ports:
  - "3020:80"    # Cleartext HTTP
  - "3021:443"   # HTTPS with TLS
  - "3024:5432"  # Layer4 standalone
```

Your Caddyfile would be:

```caddyfile
{
    debug
}

# Port 3021 maps to :443 - HTTPS server handles TLS
https://:443 {
    tls internal {
        on_demand
    }
    
    # Layer4 listener_wrapper for PostgreSQL over HTTPS
    listener_wrappers {
        layer4 {
            @postgres_tls {
                tls
                postgres
            }
            route @postgres_tls {
                # TLS already terminated by HTTPS server
                proxy db:5432
            }
        }
    }
    
    # Regular HTTPS responses
    respond "OK"
}

# Port 3024 maps to :5432 - Layer4 standalone server
layer4 {
    :5432 {
        # Option A: Cleartext only
        route {
            @postgres postgres
            route @postgres {
                proxy db:5432
            }
        }
        
        # Option B: TLS with route-level handler
        # route {
        #     tls {
        #         connection_policy {
        #         }
        #     }
        #     @postgres postgres
        #     route @postgres {
        #         proxy db:5432
        #     }
        # }
    }
}
```

## Testing Your Configuration

### Test Cleartext Connection
```bash
PGHOST=localhost PGPORT=5432 PGUSER=myuser psql -d mydb -c 'SELECT 1;'
```

### Test TLS Connection
```bash
PGSSLMODE=require PGHOST=localhost PGPORT=5432 PGUSER=myuser psql -d mydb -c 'SELECT 1;'
```

### Test with SNI (Server Name Indication)
```bash
PGSSLMODE=require PGSSLSNI=1 PGHOST=example.com PGPORT=5432 PGUSER=myuser psql -d mydb -c 'SELECT 1;'
```

## Debugging

Enable debug logging to see connection handling:

```caddyfile
{
    debug
}
```

Look for these log messages:
- `"layer4","msg":"handling connection"` - Connection accepted
- `"layer4.handlers.tls","msg":"TLS handler invoked"` - TLS handler started
- `"layer4.handlers.tls","msg":"terminated TLS"` - TLS handshake succeeded
- `"layer4.matchers.postgres","msg":"matching raw connection"` - Postgres matcher running

## Common Issues

### Issue: "connection refused" or "no route to host"
**Solution:** Check that the backend address is correct and reachable.

### Issue: "SSL error: unexpected eof while reading"
**Solution:** TLS handshake failed. Check:
- The TLS handler is configured in the route
- Certificates are available
- Client trusts the certificate (or use `PGSSLMODE=require` without verification for testing)

### Issue: Connection times out with no logs
**Solution:** The matcher isn't matching. Check:
- Connection is reaching Caddy (verify with `netstat` or `lsof`)
- Matcher configuration is correct
- Debug logging is enabled to see matching attempts

## References

- [Caddy Layer4 Documentation](https://github.com/mholt/caddy-l4)
- [PostgreSQL SSL Documentation](https://www.postgresql.org/docs/current/libpq-ssl.html)
- [Caddy TLS Documentation](https://caddyserver.com/docs/caddyfile/directives/tls)