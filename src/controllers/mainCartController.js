// src/controllers/mainCartControllers.js

import { PrismaClient } from '@prisma/client';
import { nanoid } from 'nanoid';
const prisma = new PrismaClient();


export const createCart = async (req, res) => {
  try {
    const { name } = req.body;
    const invitationLink = nanoid();
    const cart = await prisma.cart.create({
      data: {
        name,
        invitationLink,
      },
    });
    res.status(201).json(cart);
  } catch (error) {
    res.status(500).json({ error: 'Error creating cart' });
  }
};


export const getCart = async (req, res) => {
  try {
    const cart = await prisma.cart.findUnique({
      where: { id: req.params.id },
      include: { products: true },
    });
    if (cart) {
      res.json(cart);
    } else {
      res.status(404).json({ error: 'Cart not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Error fetching cart' });
  }
};

export const addProductToCart = async (req, res) => {
  try {
    const { productId } = req.body;
    const { id } = req.params;
    // Check if the cart exists
    const cart = await prisma.cart.findUnique({ where: { id } });
    if (!cart) {
      return res.status(404).json({ error: 'Cart not found' });
    }

    // Add the product to the cart
    const cartProduct = await prisma.cartProduct.create({
      data: {
        cartId: id,
        productId,
      },
    });

    // Retrieve the product details to return to the frontend
    const product = await prisma.product.findUnique({
      where: { id: productId }
    });
    res.status(201).json({ message: 'Product added to cart', product });
  } catch (error) {
    res.status(500).json({ error: 'Error adding product to cart' });
  }
};

export const removeProductFromCart = async (req, res) => {
  try {
    const { cartId, productId } = req.params;
    await prisma.cartProduct.deleteMany({
      where: { cartId, productId },
    });
    res.json({ message: 'Product removed from cart' });
  } catch (error) {
    res.status(500).json({ error: 'Error removing product from cart' });
  }
};

export const getSharedCart = async (req, res) => {
  try {
    const { link } = req.params;
    const cart = await prisma.cart.findUnique({
      where: { invitationLink: link },
      include: { products: true, users: true },
    });
    if (cart) {
      res.json(cart);
    } else {
      res.status(404).json({ error: 'Shared cart not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Error fetching shared cart' });
  }
};
