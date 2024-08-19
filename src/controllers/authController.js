import jwt from 'jsonwebtoken';
import prisma from '../models/prismaClient.js';
import { generateSalt, hashPassword } from '../utils/cryptoUtils.js';

export const signup = async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists. Please log in.' });
    }

    const salt = generateSalt();
    const hashedPassword = hashPassword(password, salt);

    const newUser = await prisma.user.create({
      data: {
        name: username,
        email,
        password: hashedPassword,
        salt,
      },
    });

    const token = jwt.sign({ userId: newUser.id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.cookie('jwt', token, { httpOnly: true, maxAge: 3600000 });

    return res.json({ message: 'User signed up successfully', user: newUser, token });
  } catch (error) {
    console.error('Signup Error:', error);
    return res.status(500).json({ message: 'Internal Server Error' });
  }
};

export const login = async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ name: username }, { email: email }],
      },
    });

    if (!existingUser) {
      return res.status(401).json({ message: 'Incorrect username or password' });
    }

    const hashedPassword = hashPassword(password, existingUser.salt);

    if (hashedPassword !== existingUser.password) {
      return res.status(401).json({ message: 'Incorrect username or password' });
    }

    const token = jwt.sign({ userId: existingUser.id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.cookie('jwt', token, { httpOnly: true, maxAge: 3600000 });

    // Check if the user has a previously generated shared cart
    const userCart = await prisma.userCart.findFirst({
      where: { userId: existingUser.id },
      include: { cart: true },
    });

    let cartId = null;
    if (userCart) {
      cartId = userCart.cart.id;
    }

    return res.json({
      message: 'Login successful',
      user: existingUser,
      token,
      cartId,
    });
  } catch (error) {
    console.error('Login Error:', error);
    return res.status(500).json({ message: 'Internal Server Error' });
  }
};

export const logout = (req, res) => {
  res.clearCookie('jwt', { path: '/' });
  return res.json({ message: 'Logout successful' });
};

export const checkAuth = async (req, res) => {
  // Extract the token from the Authorization header
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Extract the token after 'Bearer '

  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify the token
      const user = await prisma.user.findUnique({
        where: { id: decoded.userId },
      });
      if (user) {
        return res.json({ user }); // Return the user data if found
      } else {
        return res.status(404).json({ message: 'User not found' });
      }
    } catch (error) {
      console.error('Token Verification Error:', error);
      return res.status(403).json({ message: 'Forbidden' }); // Token invalid or expired
    }
  }

  return res.status(401).json({ message: 'Unauthorized' }); // No token provided
};
