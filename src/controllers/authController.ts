// src/controllers/authController.ts

import { Request, Response, NextFunction } from 'express';
import { AuthenticatedRequest, UserPayload } from '../types/types';
import { authService } from '../services/authService';

export const register = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { username, email, password, role } = req.body;

    // Validate input
    if (!username || !email || !password || !role) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const newUser = await authService.register(username, email, password, role);
    const token = authService.generateToken(newUser);

    res.status(201).json({
      token,
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role
      }
    });
  } catch (error) {
    if (error instanceof Error && error.message === 'User already exists') {
      return res.status(400).json({ message: error.message });
    }
    next(error);
  }
};

export const login = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await authService.login(email, password);
    const token = authService.generateToken(user);

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    if (error instanceof Error && error.message === 'Invalid credentials') {
      return res.status(400).json({ message: error.message });
    }
    next(error);
  }
};

export const getCurrentUser = (req: AuthenticatedRequest, res: Response) => {
  try {
    const user = req.user as UserPayload;
    
    if (!user) {
      return res.status(401).json({ message: 'Not authenticated' });
    }

    const fullUser = authService.getUserById(user.id);

    if (!fullUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      user: {
        id: fullUser.id,
        username: fullUser.username,
        email: fullUser.email,
        role: fullUser.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

export const logout = (req: AuthenticatedRequest, res: Response) => {
  res.json({ message: 'Logged out successfully' });
};

export const forgotPassword = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    await authService.forgotPassword(email);

    res.json({ message: 'If a user with that email exists, a password reset link has been sent.' });
  } catch (error) {
    next(error);
  }
};

export const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ message: 'Token and new password are required' });
    }

    await authService.resetPassword(token, newPassword);

    res.json({ message: 'Password has been reset successfully' });
  } catch (error) {
    if (error instanceof Error && error.message === 'Invalid or expired token') {
      return res.status(400).json({ message: error.message });
    }
    next(error);
  }
};

export const updateUser = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  try {
    const userId = req.user?.id;
    const { username, email } = req.body;

    if (!userId) {
      return res.status(401).json({ message: 'Not authenticated' });
    }

    const updatedUser = await authService.updateUser(userId, username, email);

    res.json({
      user: {
        id: updatedUser.id,
        username: updatedUser.username,
        email: updatedUser.email,
        role: updatedUser.role
      }
    });
  } catch (error) {
    if (error instanceof Error && error.message === 'User not found') {
      return res.status(404).json({ message: error.message });
    }
    next(error);
  }
};

export const deleteUser = async (req: AuthenticatedRequest, res: Response) => {
    try {
      const userId = req.user?.id;
  
      if (!userId) {
        return res.status(401).json({ message: 'Not authenticated' });
      }
  
      await authService.deleteUser(userId);
  
      res.json({ message: 'User deleted successfully' });
    } catch (error) {
      if (error instanceof Error && error.message === 'User not found') {
        return res.status(404).json({ message: error.message });
      }
      res.status(500).json({ message: 'Server error' });
    }
  };