import { Request } from 'express';

export interface UserPayload {
  id: number;
  role: string;
  email: string;
}

export interface AuthenticatedRequest extends Request {
  user?: UserPayload;
}