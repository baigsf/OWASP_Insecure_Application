// VULNERABILITY: Hardcoded secrets in source code
module.exports = {
  database: {
    host: 'localhost',
    user: 'root',
    password: 'rootpassword',
    database: 'vulndb'
  },
  jwt: {
    secret: 'hardcoded-jwt-secret',
    expiresIn: '24h'
  },
  aws: {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  },
  session: {
    secret: 'session-secret-hardcoded',
    cookie: {
      httpOnly: false,
      secure: false,
      sameSite: 'none'
    }
  },
  debug: true,
  csrf: false
};
