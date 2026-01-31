const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '3k9jf0s9dfj90sdjf90sdjf90sdjf90sdjf90sdjf90sdjf90sdjf90sdjf';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://teamgensourei.github.io/';

// In-memory database
const users = new Map();
const sessions = new Map();

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10
});

// Validation functions
function validatePassword(password) {
  return password.length >= 8 &&
         /[A-Z]/.test(password) &&
         /[a-z]/.test(password) &&
         /[0-9]/.test(password);
}

// Verify Scratch user exists
async function verifyScratchUser(username) {
  try {
    const response = await fetch(`https://api.scratch.mit.edu/users/${username}`);
    if (!response.ok) return null;
    const data = await response.json();
    return {
      id: data.id,
      username: data.username,
      scratchTeam: data.scratchteam || false
    };
  } catch (error) {
    console.error('Scratch API error:', error);
    return null;
  }
}

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString()
  });
});

// Step 1: Verify Scratch account
app.post('/api/verify-scratch', authLimiter, async (req, res) => {
  try {
    const { scratchUsername, email } = req.body;

    if (!scratchUsername || !email) {
      return res.status(400).json({ 
        error: 'Scratchユーザー名とメールアドレスを入力してください' 
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        error: '有効なメールアドレスを入力してください' 
      });
    }

    // Check if already registered
    const existingUser = Array.from(users.values()).find(
      u => u.scratchUsername.toLowerCase() === scratchUsername.toLowerCase()
    );

    if (existingUser) {
      return res.status(409).json({ 
        error: 'このScratchアカウントは既に登録されています' 
      });
    }

    // Verify Scratch user exists
    const scratchUser = await verifyScratchUser(scratchUsername);
    
    if (!scratchUser) {
      return res.status(404).json({ 
        error: 'Scratchユーザーが見つかりません。ユーザー名を確認してください。' 
      });
    }

    res.json({
      message: 'Scratchアカウントを確認しました',
      scratchUser: {
        id: scratchUser.id,
        username: scratchUser.username
      },
      verified: true
    });
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// Step 2: Complete registration with password
app.post('/api/complete-registration', authLimiter, async (req, res) => {
  try {
    const { scratchUsername, email, password } = req.body;

    if (!scratchUsername || !email || !password) {
      return res.status(400).json({ 
        error: 'すべてのフィールドを入力してください' 
      });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ 
        error: 'パスワードは8文字以上で、大文字、小文字、数字を含む必要があります' 
      });
    }

    // Check if already registered
    const existingUser = Array.from(users.values()).find(
      u => u.scratchUsername.toLowerCase() === scratchUsername.toLowerCase()
    );

    if (existingUser) {
      return res.status(409).json({ 
        error: 'このScratchアカウントは既に登録されています' 
      });
    }

    // Verify Scratch user again
    const scratchUser = await verifyScratchUser(scratchUsername);
    
    if (!scratchUser) {
      return res.status(404).json({ 
        error: 'Scratchユーザーが見つかりません' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const user = {
      id: userId,
      scratchId: scratchUser.id,
      scratchUsername: scratchUser.username,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString(),
      level: 1,
      progress: {}
    };

    users.set(userId, user);

    // Create session
    const token = jwt.sign(
      { userId, scratchUsername: scratchUser.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    sessions.set(token, { userId, createdAt: Date.now() });

    res.status(201).json({
      message: 'アカウントが作成されました',
      token,
      user: {
        id: userId,
        scratchUsername: scratchUser.username,
        scratchId: scratchUser.id,
        email,
        level: 1
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// Login
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { scratchUsername, password } = req.body;

    if (!scratchUsername || !password) {
      return res.status(400).json({ 
        error: 'Scratchユーザー名とパスワードを入力してください' 
      });
    }

    const user = Array.from(users.values()).find(
      u => u.scratchUsername.toLowerCase() === scratchUsername.toLowerCase()
    );

    if (!user) {
      return res.status(401).json({ 
        error: 'Scratchユーザー名またはパスワードが正しくありません' 
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ 
        error: 'Scratchユーザー名またはパスワードが正しくありません' 
      });
    }

    const token = jwt.sign(
      { userId: user.id, scratchUsername: user.scratchUsername },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    sessions.set(token, { userId: user.id, createdAt: Date.now() });

    res.json({
      message: 'ログインしました',
      token,
      user: {
        id: user.id,
        scratchUsername: user.scratchUsername,
        scratchId: user.scratchId,
        email: user.email,
        level: user.level
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// Authentication middleware
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: '認証が必要です' });
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    if (!sessions.has(token)) {
      return res.status(401).json({ error: 'セッションが無効です' });
    }

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'トークンが無効です' });
  }
}

// Get profile
app.get('/api/profile', authenticate, (req, res) => {
  const user = users.get(req.user.userId);

  if (!user) {
    return res.status(404).json({ error: 'ユーザーが見つかりません' });
  }

  res.json({
    id: user.id,
    scratchUsername: user.scratchUsername,
    scratchId: user.scratchId,
    email: user.email,
    level: user.level,
    createdAt: user.createdAt,
    progress: user.progress
  });
});

// Logout
app.post('/api/logout', authenticate, (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader.substring(7);
  
  sessions.delete(token);
  
  res.json({ message: 'ログアウトしました' });
});

// Update progress
app.post('/api/progress', authenticate, (req, res) => {
  const user = users.get(req.user.userId);
  const { challenge, status, data } = req.body;

  if (!user) {
    return res.status(404).json({ error: 'ユーザーが見つかりません' });
  }

  if (!user.progress) {
    user.progress = {};
  }

  user.progress[challenge] = {
    status,
    data,
    timestamp: new Date().toISOString()
  };

  res.json({ 
    message: '進捗を保存しました',
    progress: user.progress 
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
