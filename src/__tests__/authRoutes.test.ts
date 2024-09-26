import request from 'supertest';
import express from 'express';
import jwt from 'jsonwebtoken';
import authRouter from '../routes/authRoutes';
import { authService } from '../services/authService';

const app = express();
app.use(express.json());
app.use('/auth', authRouter);

jest.mock('../services/authService');
jest.mock('jsonwebtoken');

describe('Auth Routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /auth/register', () => {
    it('should register a new user successfully', async () => {
      const mockUser = {
        id: 1,
        username: 'testuser',
        email: 'test@example.com',
        role: 'student'
      };
      (authService.register as jest.Mock).mockResolvedValue(mockUser);
      (authService.generateToken as jest.Mock).mockReturnValue('mock_token');

      const response = await request(app)
        .post('/auth/register')
        .send({
          username: 'testuser',
          email: 'test@example.com',
          password: 'password123',
          role: 'student'
        });

      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty('token', 'mock_token');
      expect(response.body.user).toEqual(mockUser);
    });

    it('should return 400 if required fields are missing', async () => {
      const response = await request(app)
        .post('/auth/register')
        .send({
          username: 'testuser',
          email: 'test@example.com'
        });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('message', 'All fields are required');
    });

    it('should return 400 if user already exists', async () => {
      (authService.register as jest.Mock).mockRejectedValue(new Error('User already exists'));

      const response = await request(app)
        .post('/auth/register')
        .send({
          username: 'existinguser',
          email: 'existing@example.com',
          password: 'password123',
          role: 'student'
        });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('message', 'User already exists');
    });
  });

  describe('POST /auth/login', () => {
    it('should login user successfully', async () => {
      const mockUser = {
        id: 1,
        username: 'testuser',
        email: 'test@example.com',
        role: 'student'
      };
      (authService.login as jest.Mock).mockResolvedValue(mockUser);
      (authService.generateToken as jest.Mock).mockReturnValue('mock_token');

      const response = await request(app)
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123'
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('token', 'mock_token');
      expect(response.body.user).toEqual(mockUser);
    });

    it('should return 400 if email or password is missing', async () => {
      const response = await request(app)
        .post('/auth/login')
        .send({
          email: 'test@example.com'
        });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('message', 'Email and password are required');
    });

    it('should return 400 for invalid credentials', async () => {
      (authService.login as jest.Mock).mockRejectedValue(new Error('Invalid credentials'));

      const response = await request(app)
        .post('/auth/login')
        .send({
          email: 'wrong@example.com',
          password: 'wrongpassword'
        });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('message', 'Invalid credentials');
    });
  });

  describe('GET /auth/me', () => {
    it('should return current user information', async () => {
      const mockUser = {
        id: 1,
        username: 'testuser',
        email: 'test@example.com',
        role: 'student'
      };
      (jwt.verify as jest.Mock).mockReturnValue({ userId: '1', role: 'student', email: 'test@example.com' });
      (authService.getUserById as jest.Mock).mockReturnValue(mockUser);

      const response = await request(app)
        .get('/auth/me')
        .set('Authorization', 'Bearer mock_token');

      expect(response.status).toBe(200);
      expect(response.body.user).toEqual(mockUser);
    });

    it('should return 401 if not authenticated', async () => {
      const response = await request(app)
        .get('/auth/me');

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('message', 'No token provided');
    });
  });

  describe('POST /auth/logout', () => {
    it('should logout user successfully', async () => {
      (jwt.verify as jest.Mock).mockReturnValue({ userId: '1', role: 'student', email: 'test@example.com' });

      const response = await request(app)
        .post('/auth/logout')
        .set('Authorization', 'Bearer mock_token');

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('message', 'Logged out successfully');
    });

    it('should return 401 if not authenticated', async () => {
      const response = await request(app)
        .post('/auth/logout');

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('message', 'No token provided');
    });
  });

  describe('POST /auth/forgot-password', () => {
    it('should initiate password reset process', async () => {
      const response = await request(app)
        .post('/auth/forgot-password')
        .send({ email: 'test@example.com' });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('message', 'If a user with that email exists, a password reset link has been sent.');
    });

    it('should return 400 if email is missing', async () => {
      const response = await request(app)
        .post('/auth/forgot-password')
        .send({});

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('message', 'Email is required');
    });
  });

  describe('POST /auth/reset-password', () => {
    it('should reset password successfully', async () => {
      const response = await request(app)
        .post('/auth/reset-password')
        .send({
          token: 'valid_token',
          newPassword: 'newpassword123'
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('message', 'Password has been reset successfully');
    });

    it('should return 400 if token or new password is missing', async () => {
      const response = await request(app)
        .post('/auth/reset-password')
        .send({
          token: 'valid_token'
        });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('message', 'Token and new password are required');
    });

    it('should return 400 for invalid or expired token', async () => {
      (authService.resetPassword as jest.Mock).mockRejectedValue(new Error('Invalid or expired token'));

      const response = await request(app)
        .post('/auth/reset-password')
        .send({
          token: 'invalid_token',
          newPassword: 'newpassword123'
        });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('message', 'Invalid or expired token');
    });
  });

  describe('PUT /auth/update', () => {
    it('should update user information successfully', async () => {
      const mockUpdatedUser = {
        id: 1,
        username: 'updateduser',
        email: 'updated@example.com',
        role: 'student'
      };
      (jwt.verify as jest.Mock).mockReturnValue({ userId: '1', role: 'student', email: 'test@example.com' });
      (authService.updateUser as jest.Mock).mockResolvedValue(mockUpdatedUser);

      const response = await request(app)
        .put('/auth/update')
        .set('Authorization', 'Bearer mock_token')
        .send({
          username: 'updateduser',
          email: 'updated@example.com'
        });

      expect(response.status).toBe(200);
      expect(response.body.user).toEqual(mockUpdatedUser);
    });

    it('should return 401 if not authenticated', async () => {
      const response = await request(app)
        .put('/auth/update')
        .send({
          username: 'updateduser',
          email: 'updated@example.com'
        });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('message', 'No token provided');
    });

    it('should return 404 if user not found', async () => {
      (jwt.verify as jest.Mock).mockReturnValue({ userId: '999', role: 'student', email: 'test@example.com' });
      (authService.updateUser as jest.Mock).mockRejectedValue(new Error('User not found'));

      const response = await request(app)
        .put('/auth/update')
        .set('Authorization', 'Bearer mock_token')
        .send({
          username: 'updateduser',
          email: 'updated@example.com'
        });

      expect(response.status).toBe(404);
      expect(response.body).toHaveProperty('message', 'User not found');
    });
  });

  describe('DELETE /auth/delete', () => {
    it('should delete user successfully', async () => {
      const mockUser = {
        id: 1,
        username: 'testuser',
        email: 'test@example.com',
        role: 'student'
      };
      (jwt.verify as jest.Mock).mockReturnValue({ userId: '1', role: 'student', email: 'test@example.com' });
      (authService.deleteUser as jest.Mock).mockResolvedValue(undefined);

      const response = await request(app)
        .delete('/auth/delete')
        .set('Authorization', 'Bearer mock_token');

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('message', 'User deleted successfully');
      expect(authService.deleteUser).toHaveBeenCalledWith(1);
    });

    it('should return 401 if not authenticated', async () => {
      const response = await request(app)
        .delete('/auth/delete');

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('message', 'No token provided');
    });

    it('should return 404 if user not found', async () => {
      (jwt.verify as jest.Mock).mockReturnValue({ userId: '999', role: 'student', email: 'test@example.com' });
      (authService.deleteUser as jest.Mock).mockRejectedValue(new Error('User not found'));

      const response = await request(app)
        .delete('/auth/delete')
        .set('Authorization', 'Bearer mock_token');

      expect(response.status).toBe(404);
      expect(response.body).toHaveProperty('message', 'User not found');
    });

    it('should return 500 for server errors', async () => {
      (jwt.verify as jest.Mock).mockReturnValue({ userId: '1', role: 'student', email: 'test@example.com' });
      (authService.deleteUser as jest.Mock).mockRejectedValue(new Error('Database error'));

      const response = await request(app)
        .delete('/auth/delete')
        .set('Authorization', 'Bearer mock_token');

      expect(response.status).toBe(500);
      expect(response.body).toHaveProperty('message', 'Server error');
    });
  });
});