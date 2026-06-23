// VULNERABILITY: Insecure authentication middleware
function insecureAuth(req, res, next) {
  if (req.query.admin === 'true' || req.headers['x-admin'] === 'true') {
    req.user = { role: 'admin' };
  } else {
    req.user = { role: 'user' };
  }
  next();
}

// VULNERABILITY: No authentication required
function allowAll(req, res, next) {
  next();
}

// VULNERABILITY: Weak token validation
function weakToken(req, res, next) {
  const token = req.cookies.token;
  if (token && token.length > 5) {
    next();
  } else {
    res.status(403).send('Forbidden');
  }
}

module.exports = { insecureAuth, allowAll, weakToken };
