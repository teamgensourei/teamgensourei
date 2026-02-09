const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { Resend } = require('resend');

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '3k9jf0s9dfj90sdjf90sdjf90sdjf90sdjf90sdjf90sdjf90sdjf90sdjf';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://teamgensourei.github.io';
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const FROM_EMAIL = process.env.FROM_EMAIL || 'onboarding@resend.dev';

// Resend初期化
const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;

// In-memory database
const users = new Map();
const sessions = new Map();
const verificationCodes = new Map();

/* =========================
   ホワイトリスト
========================= */
const MANUAL_WHITELIST = [
  'sh1gure_H1SAME',  // ← 実際のユーザー名に変更 //
  'siranui_ameri',
  '-nyonyo-'
];

let whitelistCache = new Set(MANUAL_WHITELIST.map(u => u.toLowerCase()));

function isUserWhitelisted(username) {
  return whitelistCache.has(username.toLowerCase());
}

// 認証コード生成
function generateVerificationCode() {
  return crypto.randomInt(100000, 999999).toString();
}

// メール送信
async function sendVerificationEmail(email, code) {
  if (!resend) {
    // デバッグモード
    console.log(`📧 [DEBUG] Verification code for ${email}: ${code}`);
    return true;
  }
  
  try {
    const { data, error } = await resend.emails.send({
      from: FROM_EMAIL,
      to: email,
      subject: 'ECHO PROTOCOL - 認証コード',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { 
              font-family: 'Courier New', monospace; 
              background: #000; 
              color: #00ff00; 
              padding: 20px; 
            }
            .container { 
              max-width: 600px; 
              margin: 0 auto; 
              border: 2px solid #00ff00; 
              padding: 30px; 
            }
            .code { 
              font-size: 36px; 
              font-weight: bold; 
              text-align: center; 
              padding: 20px; 
              background: #001100; 
              border: 1px solid #00ff00;
              letter-spacing: 8px;
            }
            .warning { 
              color: #ffaa00; 
              margin-top: 20px; 
            }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>ECHO PROTOCOL</h1>
            <h2>認証コード</h2>
            <p>以下の認証コードを入力してください：</p>
            <div class="code">${code}</div>
            <p class="warning">⚠️ このコードは10分間有効です</p>
            <p class="warning">⚠️ このメールに心当たりがない場合は無視してください</p>
          </div>
        </body>
        </html>
      `
    });
    
    if (error) {
      console.error('Resend error:', error);
      return false;
    }
    
    console.log(`✅ Email sent to ${email} (ID: ${data.id})`);
    return true;
  } catch (error) {
    console.error('Email sending error:', error);
    return false;
  }
}

// Scratch API
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

// Middleware
app.use(cors({
  origin: [FRONTEND_URL, 'http://localhost:8000'],
  credentials: true
}));
app.use(express.json());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false
});

function validatePassword(password) {
  return password.length >= 8 &&
         /[A-Z]/.test(password) &&
         /[a-z]/.test(password) &&
         /[0-9]/.test(password);
}

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    users: users.size,
    whitelist: {
      enabled: true,
      allowedUsers: whitelistCache.size
    },
    email: {
      enabled: !!resend,
      mode: resend ? 'production' : 'debug'
    }
  });
});

app.get('/', (req, res) => {
  res.json({ 
    message: 'ECHO PROTOCOL API Server',
    version: '2.4.0',
    status: 'active',
    authMethod: 'email-verification'
  });
});

app.get('/api/whitelist', (req, res) => {
  res.json({
    count: whitelistCache.size,
    users: Array.from(whitelistCache)
  });
});

/* =========================
   登録 Step 1: コード送信
========================= */
app.post('/api/register/send-code', authLimiter, async (req, res) => {
  try {
    const { scratchUsername, email } = req.body;

    if (!scratchUsername || !email) {
      return res.status(400).json({ 
        error: 'Scratchユーザー名とメールアドレスを入力してください' 
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        error: '有効なメールアドレスを入力してください' 
      });
    }

    if (!isUserWhitelisted(scratchUsername)) {
      return res.status(403).json({ 
        error: 'このScratchアカウントは登録が許可されていません',
        code: 'NOT_WHITELISTED'
      });
    }

    const existingUser = Array.from(users.values()).find(
      u => u.scratchUsername.toLowerCase() === scratchUsername.toLowerCase()
    );

    if (existingUser) {
      return res.status(409).json({ 
        error: 'このScratchアカウントは既に登録されています' 
      });
    }

    const scratchUser = await verifyScratchUser(scratchUsername);
    
    if (!scratchUser) {
      return res.status(404).json({ 
        error: 'Scratchユーザーが見つかりません' 
      });
    }

    const code = generateVerificationCode();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    verificationCodes.set(email, {
      code,
      scratchUsername: scratchUser.username,
      scratchId: scratchUser.id,
      expiresAt
    });

    const sent = await sendVerificationEmail(email, code);

    if (!sent) {
      return res.status(500).json({ 
        error: 'メール送信に失敗しました' 
      });
    }

    res.json({
      message: '認証コードをメールに送信しました',
      email,
      expiresIn: 600
    });

  } catch (error) {
    console.error('Send code error:', error);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

/* =========================
   登録 Step 2: コード確認
========================= */
app.post('/api/register/verify-code', authLimiter, async (req, res) => {
  try {
    const { email, code, password } = req.body;

    if (!email || !code || !password) {
      return res.status(400).json({ 
        error: 'すべてのフィールドを入力してください' 
      });
    }

    const verification = verificationCodes.get(email);

    if (!verification) {
      return res.status(400).json({ 
        error: '認証コードが見つかりません。最初からやり直してください' 
      });
    }

    if (Date.now() > verification.expiresAt) {
      verificationCodes.delete(email);
      return res.status(400).json({ 
        error: '認証コードの有効期限が切れました' 
      });
    }

    if (verification.code !== code) {
      return res.status(400).json({ 
        error: '認証コードが正しくありません' 
      });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ 
        error: 'パスワードは8文字以上で、大文字、小文字、数字を含む必要があります' 
      });
    }

    if (!isUserWhitelisted(verification.scratchUsername)) {
      return res.status(403).json({ 
        error: 'このScratchアカウントは登録が許可されていません',
        code: 'NOT_WHITELISTED'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const user = {
      id: userId,
      scratchId: verification.scratchId,
      scratchUsername: verification.scratchUsername,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString(),
      level: 1,
      progress: {}
    };

    users.set(userId, user);
    verificationCodes.delete(email);

    const token = jwt.sign(
      { userId, scratchUsername: user.scratchUsername },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    sessions.set(token, { userId, createdAt: Date.now() });

    console.log(`✅ New user registered: ${user.scratchUsername}`);

    res.status(201).json({
      message: 'アカウントが作成されました',
      token,
      user: {
        id: userId,
        scratchUsername: user.scratchUsername,
        scratchId: user.scratchId,
        email,
        level: 1
      }
    });

  } catch (error) {
    console.error('Verify code error:', error);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

/* =========================
   ログイン
========================= */
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

app.post('/api/logout', authenticate, (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader.substring(7);
  
  sessions.delete(token);
  
  res.json({ message: 'ログアウトしました' });
});

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

// 期限切れコード削除
setInterval(() => {
  const now = Date.now();
  for (const [email, data] of verificationCodes.entries()) {
    if (now > data.expiresAt) {
      verificationCodes.delete(email);
    }
  }
}, 5 * 60 * 1000);

app.listen(PORT, () => {
  console.log(`✅ ECHO PROTOCOL Server running on port ${PORT}`);
  console.log(`🌐 Frontend URL: ${FRONTEND_URL}`);
  console.log(`🔐 JWT Secret: ✓ Custom secret set`);
  console.log(`📧 Email Mode: ${resend ? '✓ Production (Resend)' : '⚠️  Debug (Console only)'}`);
  console.log(`📋 Whitelist: ${Array.from(whitelistCache).join(', ')}`);
});
