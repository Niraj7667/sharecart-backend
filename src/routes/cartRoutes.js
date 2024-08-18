import express from 'express';
import { addtomain,addProductToSharedCart,allProducts,createCart, joinCart, addProductToCart,  voteProduct } from '../controllers/shareCartController.js';
import { authenticateToken } from '../middleware/authenticateToken.js';
import { getUserSharedCarts } from '../controllers/userController.js';
import { joinedCarts } from '../controllers/shareCartController.js';
import { sharedCartProducts } from '../controllers/sharedCartProducts.js';
import { deleteProduct } from '../controllers/shareCartController.js';
const router = express.Router();

router.post('/create', authenticateToken, createCart);
router.post('/join', authenticateToken, joinCart);
router.post('/addProduct', authenticateToken, addProductToCart);
//router.get('/:cartId', authenticateToken, getCart);
router.post('/vote', authenticateToken, voteProduct);
router.get('/products',allProducts);
router.post('/:cartId/add-product',authenticateToken,addProductToSharedCart);
router.post('/add-product',authenticateToken,addtomain);
// router.get('/:userId/shared-carts', getUserSharedCarts);
router.get('/joinedcarts',authenticateToken,joinedCarts);
router.get('/:cartId/products',sharedCartProducts);
router.delete('/:cartId/remove-product/:productId',authenticateToken,deleteProduct);

export default router;
