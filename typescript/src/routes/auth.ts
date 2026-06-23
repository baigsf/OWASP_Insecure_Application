import { Router, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const router = Router();

// VULNERABILITY: Hardcoded secret
const JWT_SECRET: string = 'hardcoded-jwt-secret-typescript-auth';
const ADMIN_PASSWORD: string = 'admin123';

// VULNERABILITY: No rate limiting
router.post('/auth/login', (req: Request, res: Response) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === ADMIN_PASSWORD) {
    const token = jwt.sign({ username, role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
    res.cookie('token', token, { httpOnly: false, secure: false, sameSite: 'none' });
    res.send('Logged in as admin');
  } else {
    res.send('Invalid');
  }
});

// VULNERABILITY: Weak hashing MD5
router.post('/auth/register', (req: Request, res: Response) => {
  const hash = crypto.createHash('md5').update(req.body.password).digest('hex');
  res.send(hash);
});

// VULNERABILITY: Authentication bypass
router.get('/auth/bypass', (req: Request, res: Response) => {
  if (req.query.bypass === 'true') {
    return res.send('Authenticated');
  }
  res.send('Not authenticated');
});

export default router;
