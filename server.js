const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:8000';

// Email configuration
const EMAIL_USER = process.env.EMAIL_USER; // 例: your-email@gmail.com
const EMAIL_PASS = process.env.EMAIL_PASS; // 例: your-app-password
const EMAIL_SERVICE = process.env.EMAIL_SERVICE || 'gmail';

// In-memory database (本番環境ではPostgreSQLやMongoDBを使用してください)
const users = new Map();
const sessions = new Map();
const verificationTokens = new Map(); // メール認証トークン
const loginTokens = new Map(); // マジックリンクトークン

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
  max: 5
});

// Email transporter setup
let transporter = null;

if (EMAIL_USER && EMAIL_PASS) {
  transporter = nodemailer.createTransport({
    service: EMAIL_SERVICE,
    auth: {
      user: EMAIL_USER,
      pass: EMAIL_PASS
    }
  });
  
  // Verify transporter
  transporter.verify((error, success) => {
    if (error) {
      console.error('Email configuration error:', error);
    } else {
      console.log('Email server is ready');
    }
  });
}

// Utility functions
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validateUsername(username) {
  const re = /^[a-zA-Z0-9_]{3,20}$/;
  return re.test(username);
}

function validatePassword(password) {
  return password.length >= 8 &&
         /[A-Z]/.test(password) &&
         /[a-z]/.test(password) &&
         /[0-9]/.test(password);
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Send verification email
async function sendVerificationEmail(email, username, token) {
  if (!transporter) {
    console.warn('Email not configured, skipping email send');
    return false;
  }

  const verificationUrl = `${FRONTEND_URL}/verify?token=${token}`;
  
  const mailOptions = {
    from: `"第四境界 Protocol" <${EMAIL_USER}>`,
    to: email,
    subject: '[第四境界] アカウント認証 - Identity Verification Required',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body {
            font-family: 'Courier New', monospace;
            background-color: #0a0e27;
            color: #00ff41;
            padding: 20px;
          }
          .container {
            max-width: 600px;
            margin: 0 auto;
            background: #0d1117;
            border: 2px solid #00ff41;
            padding: 30px;
            box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
          }
          .header {
            border-bottom: 2px solid #00ff41;
            padding-bottom: 20px;
            margin-bottom: 20px;
          }
          .title {
            font-size: 24px;
            font-weight: bold;
            color: #00d4ff;
            text-shadow: 0 0 10px #00d4ff;
          }
          .content {
            line-height: 1.8;
            margin: 20px 0;
          }
          .code-block {
            background: #161b22;
            border-left: 3px solid #00ff41;
            padding: 15px;
            margin: 20px 0;
            font-family: monospace;
          }
          .button {
            display: inline-block;
            padding: 15px 30px;
            background: transparent;
            border: 2px solid #00ff41;
            color: #00ff41;
            text-decoration: none;
            font-weight: bold;
            margin: 20px 0;
            transition: all 0.3s;
          }
          .button:hover {
            background: #00ff41;
            color: #0a0e27;
            box-shadow: 0 0 20px #00ff41;
          }
          .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #30363d;
            font-size: 12px;
            color: #8b949e;
          }
          .warning {
            color: #ffaa00;
            border: 1px solid #ffaa00;
            padding: 10px;
            margin: 20px 0;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="title">第四境界 :: BOUNDARY PROTOCOL</div>
          </div>
          
          <div class="content">
            <p>> SYSTEM MESSAGE: Identity verification initiated</p>
            <p>> Target: ${username}</p>
            <p>> Status: PENDING_VERIFICATION</p>
            <br>
            
            <p>新しいアイデンティティが検出されました。</p>
            <p>第四境界へのアクセスを完了するには、以下のリンクをクリックしてください：</p>
            
            <div style="text-align: center;">
              <a href="${verificationUrl}" class="button">
                → VERIFY IDENTITY ←
              </a>
            </div>
            
            <div class="code-block">
              認証コード: ${token.substring(0, 16)}...<br>
              有効期限: 24時間<br>
              セキュリティレベル: MAXIMUM
            </div>
            
            <div class="warning">
              ⚠ WARNING: このリンクを他人と共有しないでください<br>
              ⚠ 認証は24時間以内に完了する必要があります
            </div>
            
            <p>> 認証が完了すると、第四境界へのフルアクセスが許可されます。</p>
          </div>
          
          <div class="footer">
            <p>このメールに心当たりがない場合は、無視してください。</p>
            <p>ECHO_PROTOCOL v2.3.7 :: SECURE BOUNDARY SYSTEM</p>
          </div>
        </div>
      </body>
      </html>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Verification email sent to:', email);
    return true;
  } catch (error) {
    console.error('Error sending email:', error);
    return false;
  }
}

// Send magic link email
async function sendMagicLinkEmail(email, username, token) {
  if (!transporter) {
    console.warn('Email not configured, skipping email send');
    return false;
  }

  const loginUrl = `${FRONTEND_URL}/magic-login?token=${token}`;
  
  const mailOptions = {
    from: `"第四境界 Protocol" <${EMAIL_USER}>`,
    to: email,
    subject: '[第四境界] ログインリンク - Access Link Generated',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body {
            font-family: 'Courier New', monospace;
            background-color: #0a0e27;
            color: #00ff41;
            padding: 20px;
          }
          .container {
            max-width: 600px;
            margin: 0 auto;
            background: #0d1117;
            border: 2px solid #00d4ff;
            padding: 30px;
            box-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
          }
          .header {
            border-bottom: 2px solid #00d4ff;
            padding-bottom: 20px;
            margin-bottom: 20px;
          }
          .title {
            font-size: 24px;
            font-weight: bold;
            color: #00d4ff;
            text-shadow: 0 0 10px #00d4ff;
          }
          .content {
            line-height: 1.8;
            margin: 20px 0;
          }
          .code-block {
            background: #161b22;
            border-left: 3px solid #00d4ff;
            padding: 15px;
            margin: 20px 0;
            font-family: monospace;
          }
          .button {
            display: inline-block;
            padding: 15px 30px;
            background: transparent;
            border: 2px solid #00d4ff;
            color: #00d4ff;
            text-decoration: none;
            font-weight: bold;
            margin: 20px 0;
            transition: all 0.3s;
          }
          .button:hover {
            background: #00d4ff;
            color: #0a0e27;
            box-shadow: 0 0 20px #00d4ff;
          }
          .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #30363d;
            font-size: 12px;
            color: #8b949e;
          }
          .warning {
            color: #ffaa00;
            border: 1px solid #ffaa00;
            padding: 10px;
            margin: 20px 0;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="title">第四境界 :: ACCESS GRANTED</div>
          </div>
          
          <div class="content">
            <p>> SYSTEM MESSAGE: Login request detected</p>
            <p>> Identity: ${username}</p>
            <p>> Status: AWAITING_CONFIRMATION</p>
            <br>
            
            <p>ログインリクエストを検出しました。</p>
            <p>以下のリンクをクリックして、第四境界へアクセスしてください：</p>
            
            <div style="text-align: center;">
              <a href="${loginUrl}" class="button">
                → ACCESS BOUNDARY ←
              </a>
            </div>
            
            <div class="code-block">
              アクセストークン: ${token.substring(0, 16)}...<br>
              有効期限: 15分<br>
              セキュリティレベル: HIGH
            </div>
            
            <div class="warning">
              ⚠ WARNING: このリンクは一度のみ使用可能です<br>
              ⚠ 15分以内にアクセスしてください
            </div>
            
            <p>> リンクをクリックすると、自動的にログインされます。</p>
          </div>
          
          <div class="footer">
            <p>このリクエストに心当たりがない場合は、すぐにアカウントを確認してください。</p>
            <p>ECHO_PROTOCOL v2.3.7 :: SECURE BOUNDARY SYSTEM</p>
          </div>
        </div>
      </body>
      </html>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Magic link email sent to:', email);
    return true;
  } catch (error) {
    console.error('Error sending email:', error);
    return false;
  }
}

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    emailConfigured: !!transporter 
  });
});

// Register with email verification
app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ 
        error: 'すべてのフィールドを入力してください' 
      });
    }

    if (!validateUsername(username)) {
      return res.status(400).json({ 
        error: 'ユーザー名は3-20文字の英数字とアンダースコアのみ使用できます' 
      });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ 
        error: '有効なメールアドレスを入力してください' 
      });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ 
        error: 'パスワードは8文字以上で、大文字、小文字、数字を含む必要があります' 
      });
    }

    // Check duplicates
    const existingUser = Array.from(users.values()).find(
      u => u.username === username || u.email === email
    );

    if (existingUser) {
      return res.status(409).json({ 
        error: 'ユーザー名またはメールアドレスが既に使用されています' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const user = {
      id: userId,
      username,
      email,
      password: hashedPassword,
      verified: !transporter, // Auto-verify if email not configured
      createdAt: new Date().toISOString(),
      level: 1,
      progress: {}
    };

    users.set(userId, user);

    // If email is configured, send verification email
    if (transporter) {
      const token = generateToken();
      verificationTokens.set(token, {
        userId,
        email,
        createdAt: Date.now(),
        expiresAt: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
      });

      await sendVerificationEmail(email, username, token);

      res.status(201).json({
        message: 'アカウントが作成されました。メールアドレスを確認してください。',
        userId,
        requiresVerification: true
      });
    } else {
      // If email not configured, auto-login
      const token = jwt.sign(
        { userId, username },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      sessions.set(token, { userId, createdAt: Date.now() });

      res.status(201).json({
        message: 'アカウントが作成されました',
        token,
        user: {
          id: userId,
          username,
          email,
          level: 1,
          verified: true
        },
        requiresVerification: false
      });
    }
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// Verify email
app.get('/api/verify-email', async (req, res) => {
  try {
    const { token } = req.query;

    if (!token) {
      return res.status(400).json({ error: 'トークンが必要です' });
    }

    const verification = verificationTokens.get(token);

    if (!verification) {
      return res.status(404).json({ error: '無効なトークンです' });
    }

    if (Date.now() > verification.expiresAt) {
      verificationTokens.delete(token);
      return res.status(410).json({ error: 'トークンの有効期限が切れています' });
    }

    const user = users.get(verification.userId);

    if (!user) {
      return res.status(404).json({ error: 'ユーザーが見つかりません' });
    }

    // Verify user
    user.verified = true;
    users.set(user.id, user);
    verificationTokens.delete(token);

    // Create session
    const jwtToken = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    sessions.set(jwtToken, { userId: user.id, createdAt: Date.now() });

    res.json({
      message: 'メール認証が完了しました',
      token: jwtToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        level: user.level,
        verified: true
      }
    });
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// Request magic link (passwordless login)
app.post('/api/request-magic-link', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'メールアドレスを入力してください' });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ error: '有効なメールアドレスを入力してください' });
    }

    // Find user
    const user = Array.from(users.values()).find(u => u.email === email);

    if (!user) {
      // Don't reveal if user exists or not
      return res.json({ 
        message: 'ログインリンクをメールで送信しました（存在する場合）' 
      });
    }

    if (!user.verified) {
      return res.status(403).json({ 
        error: 'アカウントが未認証です。メールを確認してください' 
      });
    }

    // Generate magic link token
    const token = generateToken();
    loginTokens.set(token, {
      userId: user.id,
      email: user.email,
      createdAt: Date.now(),
      expiresAt: Date.now() + 15 * 60 * 1000, // 15 minutes
      used: false
    });

    await sendMagicLinkEmail(email, user.username, token);

    res.json({ 
      message: 'ログインリンクをメールで送信しました' 
    });
  } catch (error) {
    console.error('Magic link request error:', error);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// Login with magic link
app.get('/api/magic-login', async (req, res) => {
  try {
    const { token } = req.query;

    if (!token) {
      return res.status(400).json({ error: 'トークンが必要です' });
    }

    const loginToken = loginTokens.get(token);

    if (!loginToken) {
      return res.status(404).json({ error: '無効なトークンです' });
    }

    if (loginToken.used) {
      return res.status(410).json({ error: 'このトークンは既に使用されています' });
    }

    if (Date.now() > loginToken.expiresAt) {
      loginTokens.delete(token);
      return res.status(410).json({ error: 'トークンの有効期限が切れています' });
    }

    const user = users.get(loginToken.userId);

    if (!user) {
      return res.status(404).json({ error: 'ユーザーが見つかりません' });
    }

    // Mark token as used
    loginToken.used = true;
    loginTokens.set(token, loginToken);

    // Create session
    const jwtToken = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    sessions.set(jwtToken, { userId: user.id, createdAt: Date.now() });

    // Delete the magic link token
    setTimeout(() => loginTokens.delete(token), 5000);

    res.json({
      message: 'ログインしました',
      token: jwtToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        level: user.level,
        verified: user.verified
      }
    });
  } catch (error) {
    console.error('Magic login error:', error);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// Traditional login (kept for backwards compatibility)
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ 
        error: 'ユーザー名とパスワードを入力してください' 
      });
    }

    const user = Array.from(users.values()).find(
      u => u.username === username || u.email === username
    );

    if (!user) {
      return res.status(401).json({ 
        error: 'ユーザー名またはパスワードが正しくありません' 
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ 
        error: 'ユーザー名またはパスワードが正しくありません' 
      });
    }

    if (!user.verified) {
      return res.status(403).json({ 
        error: 'アカウントが未認証です。メールを確認してください' 
      });
    }

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    sessions.set(token, { userId: user.id, createdAt: Date.now() });

    res.json({
      message: 'ログインしました',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        level: user.level,
        verified: user.verified
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
    username: user.username,
    email: user.email,
    level: user.level,
    verified: user.verified,
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
  console.log(`Email configured: ${!!transporter}`);
});
