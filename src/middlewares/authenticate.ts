import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { AuthenticatedRequest } from '../types/types';

interface DecodedToken {
  userId: string;
  role: string;
  email: string;
  // Add any other properties that are included in your JWT payload
}

export const authenticate = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    // Get the token from the Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      res.status(401).json({ message: 'No token provided' });
      return;
    }

    // Check if the header starts with 'Bearer '
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      res.status(401).json({ message: 'Token error' });
      return;
    }

    const token = parts[1];

    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as DecodedToken;

    // If verification is successful, set the user information on the request object
    (req as AuthenticatedRequest).user = {
      id: parseInt(decoded.userId),
      role: decoded.role,
      email: decoded.email,
    };
    
    // const user = await User.findById(parseInt(decoded.userId));
    // if (!user) {
    //   res.status(401).json({ message: 'User not found' });
    //   return;
    // }

    // If everything is okay, proceed to the next middleware or route handler
    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      // Handle specific JWT errors
      if (error.name === 'TokenExpiredError') {
        res.status(401).json({ message: 'Token expired' });
      } else {
        res.status(401).json({ message: 'Invalid token' });
      }
    } else {
      // Handle any other errors
      console.error('Authentication error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }
};