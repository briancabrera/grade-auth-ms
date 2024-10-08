import express from 'express';
import { Request, Response, NextFunction } from 'express';
import {
  register,
  login,
  logout,
  forgotPassword,
  resetPassword
} from '../controllers/authController';
import { authenticate } from '../middlewares/authenticate';
import { AuthenticatedRequest } from '../types/types';

const authRouter = express.Router();

// Public routes
authRouter.post('/register', (req: Request, res: Response, next: NextFunction) => {
  register(req, res, next).catch(next);
});

authRouter.post('/login', (req: Request, res: Response, next: NextFunction) => {
  login(req, res, next).catch(next);
});

authRouter.post('/forgot-password', (req: Request, res: Response, next: NextFunction) => {
  forgotPassword(req, res, next).catch(next);
});

authRouter.post('/reset-password', (req: Request, res: Response, next: NextFunction) => {
  resetPassword(req, res, next).catch(next);
});

// Protected routes
authRouter.post('/logout', authenticate, async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
        logout(req, res);
    } catch (error) {
        next(error);
    }
});

export default authRouter;