# VULNERABILITY: Hardcoded secrets in source code
DATABASE_URL = "postgresql://admin:SuperSecretPassword@localhost:5432/vulndb"
REDIS_PASSWORD = "redis-password-123"
SMTP_PASSWORD = "smtp-secret-password"
JWT_SECRET = "hardcoded-jwt-secret"
ENCRYPTION_KEY = "0123456789abcdef"

# VULNERABILITY: Debug mode
DEBUG = True

# VULNERABILITY: Disabled CSRF protection
CSRF_ENABLED = False

# VULNERABILITY: Permissive CORS
CORS_ORIGINS = ["*"]

# VULNERABILITY: Weak session settings
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_SAMESITE = None
