
import jwt from 'jsonwebtoken';
import prisma from '../models/prismaClient.js';

export const authenticateToken = async (req, res, next) => {
  const token = req.cookies.jwt;
  
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
        return res.redirect('/logout');
      }
    }
  } else {
    res.status(401).json({ message: 'Unauthorized' });
  }
};
