// src/services/authService.ts

import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

interface User {
  id: number;
  username: string;
  email: string;
  password: string;
  role: 'student' | 'teacher' | 'parent' | 'moderator' | 'admin';
}

// This is a mock DB
const users: User[] = [];

export class AuthService {
  async register(username: string, email: string, password: string, role: User['role']): Promise<User> {
    // Check if user already exists
    const existingUser = users.find(user => user.email === email);
    if (existingUser) {
      throw new Error('User already exists');
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const newUser: User = {
      id: users.length + 1,
      username,
      email,
      password: hashedPassword,
      role
    };
    users.push(newUser);

    return newUser;
  }

  async login(email: string, password: string): Promise<User> {
    // Find user
    const user = users.find(user => user.email === email);
    if (!user) {
      throw new Error('Invalid credentials');
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new Error('Invalid credentials');
    }

    return user;
  }

  generateToken(user: User): string {
    return jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET || 'your_jwt_secret',
      { expiresIn: '1d' }
    );
  }

  getUserById(id: number): User | undefined {
    return users.find(user => user.id === id);
  }

  async forgotPassword(email: string): Promise<void> {
    const user = users.find(user => user.email === email);
    if (!user) {
      // For security reasons, don't reveal that the user doesn't exist
      return;
    }

    // In a real application, you would generate a password reset token and send an email here
    console.log(`Password reset requested for user: ${user.email}`);
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    // In a real application, you would verify the token and find the user
    // For this example, we'll just pretend the token is valid and update the first user's password

    if (users.length === 0) {
      throw new Error('Invalid or expired token');
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update user's password
    users[0].password = hashedPassword;
  }

  async updateUser(userId: number, username?: string, email?: string): Promise<User> {
    const userIndex = users.findIndex(user => user.id === userId);
    if (userIndex === -1) {
      throw new Error('User not found');
    }

    if (username) users[userIndex].username = username;
    if (email) users[userIndex].email = email;

    return users[userIndex];
  }

  async deleteUser(userId: number): Promise<void> {
    const userIndex = users.findIndex(user => user.id === userId);
    if (userIndex === -1) {
      throw new Error('User not found');
    }

    // Remove the user from the array
    users.splice(userIndex, 1);

    // perform additional cleanup tasks here
    // such as deleting associated data or logging the deletion.
  }
}

export const authService = new AuthService();