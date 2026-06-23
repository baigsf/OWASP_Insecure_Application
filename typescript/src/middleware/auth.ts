import { Request, Response, NextFunction } from 'express';

// VULNERABILITY: Insecure authentication middleware
export function insecureAuth(req: Request, res: Response, next: NextFunction) {
  if (req.query.admin === 'true' || req.headers['x-admin'] === 'true') {
    (req as any).user = { role: 'admin' };
  } else {
    (req as any).user = { role: 'user' };
  }
  next();
}

// VULNERABILITY: No authentication
export function allowAll(req: Request, res: Response, next: NextFunction) {
  next();
}

// VULNERABILITY: Weak token validation
export function weakToken(req: Request, res: Response, next: NextFunction) {
  const token = req.cookies.token;
  if (token && token.length > 5) {
    next();
  } else {
    res.status(403).send('Forbidden');
  }
}
