// src/routes/mainCartRoutes.js

import express from 'express';
import { createCart, getCart, addProductToCart, removeProductFromCart, getSharedCart } from '../controllers/mainCartControllers.js';

const router = express.Router();

// Create a new cart
router.post('/carts', createCart);

// Get cart details
router.get('/carts/:id', getCart);

// Add product to cart
router.post('/carts/:id/products', addProductToCart);

// Remove product from cart
router.delete('/carts/:cartId/products/:productId', removeProductFromCart);

// Get shared cart details
router.get('/carts/shared/:link', getSharedCart);

export default router;
