import jwt from 'jsonwebtoken';
import prisma from '../models/prismaClient.js';

export const authenticateToken = async (req, res, next) => {
  // Extract the token from the Authorization header
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer token

  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = await prisma.user.findUnique({
        where: { id: decoded.userId },
      });
      
      if (!req.user) {
        return res.status(401).json({ message: 'Unauthorized - Invalid user' });
      }

      next();
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        return res.status(403).json({ message: 'Forbidden - Invalid token' }); // Changed redirect to appropriate error
      }
      res.status(500).json({ message: 'Internal server error' });
    }
  } else {
    res.status(401).json({ message: 'Unauthorized - No token provided' });
  }
};
