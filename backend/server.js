const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const connectDB = require('./config.js/db');
const User = require('./models/User');

// Load environment variables
dotenv.config({ path: path.join(__dirname, '.env') });

const app = express();
const PORT = process.env.PORT || 5001;
const authRequests = new Map();

app.disable('x-powered-by');

// Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
  next();
});

// Rate Limiter Middleware
const authRateLimiter = (req, res, next) => {
  const key = `${req.ip}:${req.path}`;
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const maxRequests = 20;
  const requestLog = authRequests.get(key) || [];
  const recentRequests = requestLog.filter((timestamp) => now - timestamp < windowMs);

  if (recentRequests.length >= maxRequests) {
    return res.status(429).json({ msg: 'Too many authentication attempts. Please try again later.' });
  }

  recentRequests.push(now);
  authRequests.set(key, recentRequests);
  next();
};

// Standard Middleware
app.use(
  cors({
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    credentials: true
  })
);
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// --- ROUTES ---

app.get('/', (req, res) => {
  res.status(200).json({
    message: 'Welcome to the Local Marketplace API',
    status: 'running',
    endpoints: {
      auth: '/api/auth',
      health: '/api/health'
    }
  });
});

app.get('/api/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Server is healthy',
    time: new Date().toISOString()
  });
});

// IMPORTANT: Ensure ./routes/authRoutes correctly exports express.Router()
const authRoutes = require('./routes/authRoutes');
app.use('/api/auth', authRateLimiter, authRoutes);

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route not found: ${req.originalUrl}`
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal Server Error'
  });
});

// --- SERVER INITIALIZATION ---

const ensureAdminUser = async () => {
  const adminEmail = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const adminPassword = process.env.ADMIN_PASSWORD?.trim();
  const adminName = process.env.ADMIN_NAME?.trim() || 'System Admin';

  if (!adminEmail || !adminPassword) {
    console.log('Admin credentials not provided in .env, skipping admin check.');
    return;
  }

  try {
    const existingAdmin = await User.findOne({ email: adminEmail });

    if (existingAdmin) {
      existingAdmin.name = adminName;
      existingAdmin.role = 'admin';
      existingAdmin.password = adminPassword;
      existingAdmin.isVerified = true;
      existingAdmin.isBlocked = false;
      
      // The error likely triggers here or in User.create below
      await existingAdmin.save();
      console.log(`Admin account synced for ${adminEmail}`);
    } else {
      await User.create({
        name: adminName,
        email: adminEmail,
        password: adminPassword,
        role: 'admin',
        isVerified: true
      });
      console.log(`Admin account created for ${adminEmail}`);
    }
  } catch (err) {
    // We log the error but don't kill the server process
    console.error('CRITICAL: Error ensuring admin user. Check your User model middleware!');
    console.error('Details:', err);
  }
};

const startServer = async () => {
  try {
    if (!process.env.MONGO_URI) {
      throw new Error('MONGO_URI is missing. Add it in backend/.env');
    }

    if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 12) {
      throw new Error('JWT_SECRET must be set and at least 12 characters long');
    }

    // 1. Connect to DB
    await connectDB();
    
    // 2. Start Listening (Start the server first so it stays up)
    app.listen(PORT, () => {
      console.log(`Local Marketplace server running on port ${PORT}`);
    });

    // 3. Run background tasks
    await ensureAdminUser();
    
  } catch (error) {
    console.error('Failed to start server:', error.message);
    process.exit(1);
  }
};

if (require.main === module) {
  startServer();
}

module.exports = app;