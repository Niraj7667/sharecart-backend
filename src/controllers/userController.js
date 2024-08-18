// src/controllers/userController.js
import prisma from '../models/prismaClient.js';

export const getUserSharedCarts = async (req, res) => {
  const { userId } = req.params;

  try {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        carts: {
          include: {
            cart: {
              include: {
                users: true,
              },
            },
          },
        },
      },
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const sharedCarts = user.carts.map(uc => uc.cart);

    res.json(sharedCarts);
  } catch (error) {
    console.error('Error fetching user shared carts:', error);
    res.status(500).json({ error: 'Error fetching user shared carts' });
  }
};
