import express from 'express';
import { signup, login, logout ,checkAuth} from '../controllers/authController.js';
import { validateInput } from '../middleware/validate.js';

const router = express.Router();

router.post('/signup', validateInput, signup);
router.post('/login', validateInput, login);
router.post('/logout', logout);
router.get('/check', checkAuth);

export default router;
