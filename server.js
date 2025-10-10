require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient({
  log: ['error'],
});
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

// Simple CORS setup
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});
app.use(express.json());

// Input validation
const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const sanitizeString = (str) => str.replace(/[<>"'&]/g, (match) => {
  const entities = { '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;', '&': '&amp;' };
  return entities[match];
}).trim();

// Auth middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: { id: true, email: true, role: true, isLocked: true, lockUntil: true }
    });

    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (user.isLocked && user.lockUntil && new Date() < user.lockUntil) {
      return res.status(423).json({ error: 'Account is locked' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Generate tokens
const generateTokens = (userId) => {
  const accessToken = jwt.sign({ userId }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ userId }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
  return { accessToken, refreshToken };
};

// Auth routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password || !validateEmail(email)) {
      return res.status(400).json({ error: 'Valid email and password required' });
    }
    
    const user = await prisma.user.findUnique({ where: { email: sanitizeString(email.toLowerCase()) } });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check account lockout
    if (user.isLocked && user.lockUntil && new Date() < user.lockUntil) {
      const remainingTime = Math.ceil((user.lockUntil - new Date()) / 1000 / 60);
      return res.status(423).json({ error: 'Account locked', remainingTime: `${remainingTime} minutes` });
    }

    // Auto-unlock if expired
    if (user.isLocked && user.lockUntil && new Date() >= user.lockUntil) {
      await prisma.user.update({
        where: { id: user.id },
        data: { isLocked: false, lockUntil: null, failedAttempts: 0 }
      });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      const failedAttempts = user.failedAttempts + 1;
      const shouldLock = failedAttempts >= 3;

      await prisma.user.update({
        where: { id: user.id },
        data: {
          failedAttempts,
          isLocked: shouldLock,
          lockUntil: shouldLock ? new Date(Date.now() + 30 * 60 * 1000) : null
        }
      });

      if (shouldLock) {
        return res.status(423).json({ error: 'Account locked due to failed attempts. Try again in 30 minutes.' });
      }

      return res.status(401).json({ error: 'Invalid credentials', attemptsRemaining: 3 - failedAttempts });
    }

    // Reset failed attempts on success
    if (user.failedAttempts > 0) {
      await prisma.user.update({
        where: { id: user.id },
        data: { failedAttempts: 0, isLocked: false, lockUntil: null }
      });
    }

    const { accessToken, refreshToken } = generateTokens(user.id);

    // Store refresh token
    await prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: user.id,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      }
    });

    res.json({
      message: 'Login successful',
      accessToken,
      refreshToken,
      user: { id: user.id, email: user.email, role: user.role }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, role = 'USER' } = req.body;
    
    if (!email || !password || !validateEmail(email)) {
      return res.status(400).json({ error: 'Valid email and password required' });
    }
    
    if (password.length < 8 || !/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
      return res.status(400).json({ error: 'Password must be 8+ chars with uppercase, lowercase, and number' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const user = await prisma.user.create({
      data: { 
        email: sanitizeString(email.toLowerCase()), 
        password: hashedPassword, 
        role: role.toUpperCase() 
      },
      select: { id: true, email: true, role: true }
    });

    res.status(201).json({ message: 'User created successfully', user });
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(409).json({ error: 'User already exists' });
    }
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Token refresh endpoint
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token required' });
    }

    const storedToken = await prisma.refreshToken.findUnique({
      where: { token: refreshToken },
      include: { user: true }
    });

    if (!storedToken || storedToken.expiresAt < new Date()) {
      if (storedToken) await prisma.refreshToken.delete({ where: { id: storedToken.id } });
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    const { accessToken, refreshToken: newRefreshToken } = generateTokens(storedToken.userId);

    // Replace old token
    await prisma.refreshToken.delete({ where: { id: storedToken.id } });
    await prisma.refreshToken.create({
      data: {
        token: newRefreshToken,
        userId: storedToken.userId,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      }
    });

    res.json({ accessToken, refreshToken: newRefreshToken });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

// Logout endpoint
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) {
      await prisma.refreshToken.deleteMany({
        where: { token: refreshToken, userId: req.user.id }
      });
    }
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Logout failed' });
  }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// Task routes
app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const where = req.user.role === 'ADMIN' ? {} : { userId: req.user.id };
    
    const [tasks, total] = await Promise.all([
      prisma.task.findMany({
        where,
        include: { user: { select: { id: true, email: true } } },
        skip,
        take: parseInt(limit),
        orderBy: { createdAt: 'desc' }
      }),
      prisma.task.count({ where })
    ]);
    
    res.json({
      tasks,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch tasks' });
  }
});

app.post('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const { title, description } = req.body;
    
    if (!title || title.trim().length === 0) {
      return res.status(400).json({ error: 'Task title is required' });
    }
    
    if (title.length > 200 || (description && description.length > 1000)) {
      return res.status(400).json({ error: 'Title/description too long' });
    }
    
    const task = await prisma.task.create({
      data: { 
        title: sanitizeString(title), 
        description: description ? sanitizeString(description) : null, 
        userId: req.user.id 
      },
      include: { user: { select: { id: true, email: true } } }
    });
    res.status(201).json({ message: 'Task created successfully', task });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create task' });
  }
});

// Search tasks
app.post('/api/tasks/search', authenticateToken, async (req, res) => {
  try {
    const { query, page = 1, limit = 10 } = req.body;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    if (!query || typeof query !== 'string') {
      return res.status(400).json({ error: 'Search query required' });
    }
    
    let where = {
      OR: [
        { title: { contains: sanitizeString(query), mode: 'insensitive' } },
        { description: { contains: sanitizeString(query), mode: 'insensitive' } }
      ]
    };
    
    if (req.user.role !== 'ADMIN') {
      where.userId = req.user.id;
    }
    
    const [tasks, total] = await Promise.all([
      prisma.task.findMany({
        where,
        include: { user: { select: { id: true, email: true } } },
        skip,
        take: parseInt(limit),
        orderBy: { createdAt: 'desc' }
      }),
      prisma.task.count({ where })
    ]);
    
    res.json({
      tasks,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Search failed' });
  }
});

// Filter tasks
app.post('/api/tasks/filter', authenticateToken, async (req, res) => {
  try {
    const { completed, page = 1, limit = 10 } = req.body;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    let where = {};
    if (completed !== undefined) {
      where.completed = completed;
    }
    
    if (req.user.role !== 'ADMIN') {
      where.userId = req.user.id;
    }
    
    const [tasks, total] = await Promise.all([
      prisma.task.findMany({
        where,
        include: { user: { select: { id: true, email: true } } },
        skip,
        take: parseInt(limit),
        orderBy: { createdAt: 'desc' }
      }),
      prisma.task.count({ where })
    ]);
    
    res.json({
      tasks,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Filter failed' });
  }
});

app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, completed } = req.body;
    
    const existingTask = await prisma.task.findUnique({ where: { id } });
    if (!existingTask) {
      return res.status(404).json({ error: 'Task not found' });
    }

    if (req.user.role !== 'ADMIN' && existingTask.userId !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const updateData = {};
    if (title) updateData.title = sanitizeString(title);
    if (description !== undefined) updateData.description = description ? sanitizeString(description) : null;
    if (completed !== undefined) updateData.completed = completed;

    const task = await prisma.task.update({
      where: { id },
      data: updateData,
      include: { user: { select: { id: true, email: true } } }
    });

    res.json({ message: 'Task updated successfully', task });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update task' });
  }
});

app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    await prisma.task.delete({ where: { id: req.params.id } });
    res.json({ message: 'Task deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete task' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});