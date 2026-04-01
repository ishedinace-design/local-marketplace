const User = require('../models/User');
const jwt = require('jsonwebtoken');

const allowedRoles = new Set(['customer', 'provider']);
const allowedCategories = new Set(['Builder', 'Plumber', 'Electrician', 'Tailor', 'Painter', 'Carpenter', 'Cleaner', 'Mechanic']);
const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const signToken = (user) => jwt.sign(
  { id: user._id, role: user.role, email: user.email },
  process.env.JWT_SECRET,
  { expiresIn: '1d' }
);

exports.register = async (req, res) => {
  try {
    const { name, email, password, role, phoneNumber, location, category, bio } = req.body;
    const cleanName = name?.trim();
    const cleanEmail = email?.trim().toLowerCase();
    const selectedRole = role || 'customer';
    const cleanCategory = category?.trim() || '';
    const cleanBio = bio?.trim() || '';

    if (!cleanName || !cleanEmail || !password) {
      return res.status(400).json({ msg: "Name, email, and password are required" });
    }

    if (!/^\S+@\S+\.\S+$/.test(cleanEmail)) {
      return res.status(400).json({ msg: "Please enter a valid email address" });
    }

    if (password.length < 6) {
      return res.status(400).json({ msg: "Password must be at least 6 characters" });
    }

    if (!allowedRoles.has(selectedRole)) {
      return res.status(400).json({ msg: "Invalid account role selected" });
    }

    if (selectedRole === 'provider' && !allowedCategories.has(cleanCategory)) {
      return res.status(400).json({ msg: "Please choose a valid service category" });
    }

    let user = await User.findOne({ email: cleanEmail });
    if (user) return res.status(400).json({ msg: "User already exists" });

    const userData = {
      name: cleanName,
      email: cleanEmail,
      password,
      role: selectedRole,
      phoneNumber: phoneNumber?.trim() || '',
      location: location?.trim() || ''
    };

    if (selectedRole === 'provider') {
      userData.category = cleanCategory;
      userData.bio = cleanBio;
    }

    user = await User.create(userData);
    const token = signToken(user);
    res.status(201).json({
      msg: "User registered successfully",
      token,
      user: user.toSafeObject()
    });
  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ msg: err.message || "Server Error" });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password, username, identifier, name } = req.body;
    const loginValue = (identifier || email || username || name || '').trim().toLowerCase();

    if (!loginValue || !password) {
      return res.status(400).json({ msg: "Email/username and password are required" });
    }

    const user = await User.findOne({
      $or: [{ email: loginValue }, { name: new RegExp(`^${escapeRegExp(loginValue)}$`, 'i') }]
    }).select('+password');

    if (!user) return res.status(400).json({ msg: "Invalid Credentials" });

    if (user.isBlocked) {
      return res.status(403).json({ msg: 'This account has been blocked. Contact the administrator.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid Credentials" });

    const token = signToken(user);
    res.json({ token, user: user.toSafeObject() });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ msg: err.message || "Server Error" });
  }
};

exports.getUsers = async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    res.json({
      success: true,
      count: users.length,
      users: users.map((user) => user.toSafeObject())
    });
  } catch (err) {
    console.error('Get users error:', err.message);
    res.status(500).json({ msg: err.message || "Server Error" });
  }
};

exports.toggleUserBlock = async (req, res) => {
  try {
    const { id } = req.params;
    const targetUser = await User.findById(id);

    if (!targetUser) {
      return res.status(404).json({ msg: 'User not found' });
    }

    if (targetUser.role === 'admin') {
      return res.status(400).json({ msg: 'Admin accounts cannot be blocked here.' });
    }

    targetUser.isBlocked = !targetUser.isBlocked;
    await targetUser.save();

    res.json({
      success: true,
      msg: targetUser.isBlocked ? 'User blocked successfully' : 'User unblocked successfully',
      user: targetUser.toSafeObject()
    });
  } catch (err) {
    console.error('Toggle user block error:', err.message);
    res.status(500).json({ msg: err.message || 'Server Error' });
  }
};

exports.deleteUser = async (req, res) => {
  try {
    const { id } = req.params;
    const targetUser = await User.findById(id);

    if (!targetUser) {
      return res.status(404).json({ msg: 'User not found' });
    }

    if (targetUser.role === 'admin') {
      return res.status(400).json({ msg: 'Admin accounts cannot be deleted here.' });
    }

    await User.findByIdAndDelete(id);

    res.json({
      success: true,
      msg: 'User deleted successfully'
    });
  } catch (err) {
    console.error('Delete user error:', err.message);
    res.status(500).json({ msg: err.message || 'Server Error' });
  }
};
