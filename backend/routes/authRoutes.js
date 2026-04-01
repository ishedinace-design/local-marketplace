const express = require('express');
const router = express.Router();
const { register, login, getUsers, toggleUserBlock, deleteUser } = require('../controllers/authController');
const { protect, authorizeRoles } = require('../middleware/authMiddleware');

router.post('/register', register);
router.post('/login', login);
router.get('/users', protect, authorizeRoles('admin'), getUsers);
router.patch('/users/:id/block', protect, authorizeRoles('admin'), toggleUserBlock);
router.delete('/users/:id', protect, authorizeRoles('admin'), deleteUser);

module.exports = router;
