import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['creator', 'learner', 'recruiter'],
    required: true
  },
  education: {
    institution: String,
    degree: String,
    studentId: String
  },
  nationalId: String,
  isVerified: {
    type: Boolean,
    default: false
  },
  skills: [String],
  experience: [{
    title: String,
    company: String,
    duration: String,
    description: String
  }],
  achievements: [String],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

export default User;