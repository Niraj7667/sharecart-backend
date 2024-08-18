// src/routes/productRoutes.js

import express from 'express';
import { getProducts, addProduct, getProductById, updateProduct, deleteProduct } from '../controllers/productControllers.js';

const router = express.Router();

// Get all products
router.get('/products', getProducts);

// Get a single product by ID
router.get('/products/:id', getProductById);

// Add a new product
router.post('/products', addProduct);

// Update a product
router.put('/products/:id', updateProduct);

// Delete a product
router.delete('/products/:id', deleteProduct);

export default router;
