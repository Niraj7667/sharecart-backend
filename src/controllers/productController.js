// src/controllers/productControllers.js

import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export const getProducts = async (req, res) => {
  try {
    const products = await prisma.product.findMany();
    res.json(products);
  } catch (error) {
    
    res.status(500).json({ error: 'Error fetching products' });
  }
};

export const getProductById = async (req, res) => {
  try {
    const product = await prisma.product.findUnique({
      where: { id: req.params.id },
    });
    if (product) {
      res.json(product);
    } else {
      res.status(404).json({ error: 'Product not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Error fetching product' });
  }
};

// export const addProduct = async (req, res) => {
//   try {
//     const newProduct = await prisma.product.create({
//       data: req.body,
//     });
//     res.status(201).json(newProduct);
//   } catch (error) {
//     res.status(500).json({ error: 'Error creating product' });
//   }
// };

export const updateProduct = async (req, res) => {
  try {
    const updatedProduct = await prisma.product.update({
      where: { id: req.params.id },
      data: req.body,
    });
    res.json(updatedProduct);
  } catch (error) {
    res.status(500).json({ error: 'Error updating product' });
  }
};

export const deleteProduct = async (req, res) => {
  try {
    await prisma.product.delete({
      where: { id: req.params.id },
    });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Error deleting product' });
  }
}
