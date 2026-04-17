const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const providerCategories = ['Builder', 'Plumber', 'Electrician', 'Tailor', 'Painter', 'Carpenter', 'Cleaner', 'Mechanic'];

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 80
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email address']
  },
  password: {
    type: String,
    required: true,
    minlength: 6,
    select: false
  },
  role: { type: String, enum: ['customer', 'provider', 'admin'], default: 'customer' },
  location: { type: String, trim: true, maxlength: 120 },
  phoneNumber: { type: String, trim: true, maxlength: 30 },
  // Fields for Providers only
  category: {
    type: String,
    enum: [...providerCategories, ''],
    default: ''
  },
  bio: { type: String, trim: true, maxlength: 400 },
  isBlocked: { type: Boolean, default: false },
  isVerified: { type: Boolean, default: false }
}, { timestamps: true });

// CORRECTED MIDDLEWARE: Removed 'next' callback for async function
UserSchema.pre('save', async function savePassword() {
  if (!this.isModified('password')) {
    return; // Just return, don't call next()
  }

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  } catch (err) {
    throw err; // Re-throw to let Mongoose handle the error
  }
});

UserSchema.methods.comparePassword = function comparePassword(candidatePassword) {
  // Using 'this.password' requires it to be selected/available
  return bcrypt.compare(candidatePassword, this.password);
};

UserSchema.methods.toSafeObject = function toSafeObject() {
  return {
    id: this._id,
    name: this.name,
    email: this.email,
    role: this.role,
    phoneNumber: this.phoneNumber,
    location: this.location,
    category: this.category,
    bio: this.bio,
    isBlocked: this.isBlocked,
    isVerified: this.isVerified,
    createdAt: this.createdAt
  };
};

module.exports = mongoose.model('User', UserSchema);