import express from 'express';
import prisma from '../models/prismaClient.js'; // Import your Prisma client

// GET /api/cart/:cartId/products - Fetch all products in a cart
export const sharedCartProducts = async (req, res) => {
  const { cartId } = req.params;

  try {
    // Find the cart and include its products with their details and the username of the user who added them
    const cart = await prisma.cart.findUnique({
      where: { id: cartId },
      include: {
        products: {
          include: {
            product: true, // Include full product details
          },
        },
      },
    });

    if (!cart) {
      return res.status(404).json({ error: 'Cart not found' });
    }

    // Map the cart products to extract the relevant product details and the username
    const products = cart.products.map(cartProduct => ({
      productId: cartProduct.product.id,
      name: cartProduct.product.name,
      price: cartProduct.product.price,
      rating: cartProduct.product.rating,
      numRatings: cartProduct.product.numRatings,
      voteCount: cartProduct.product.voteCount,
      imageUrl: cartProduct.product.imageUrl,
      addedBy: cartProduct.username, // Include the username of the user who added the product
    }));

    // Send the products as the response
    res.json(products);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch products for the cart' });
  }
};
