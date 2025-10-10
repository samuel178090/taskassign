# Secure Task Management API

Enterprise-grade Node.js/Express API implementing JWT authentication, role-based access control (RBAC), and comprehensive security measures to mitigate OWASP Top 10 vulnerabilities.

## 🏗️ Architecture Overview

This API demonstrates production-ready security practices including:
- **JWT Authentication** with access/refresh token rotation
- **Role-Based Access Control** (USER/ADMIN permissions)
- **Account Security** with lockout protection (3 failed attempts = 30min lock)
- **Input Validation** with custom sanitization (no external libraries)
- **Security Headers** via Helmet.js (CSP, XSS protection)
- **OWASP Compliance** addressing A01 (Broken Access Control) and A03 (Injection)

## 🚀 Quick Start

### Local Development
```bash
npm install
npx prisma generate
npx prisma db push
node seed.js
npm run dev
```

### Production Deployment (Render)

1. **Web Service Configuration:**
   - Build Command: `npm install && npx prisma generate`
   - Start Command: `npm start`
   - Node Version: 18+

2. **Environment Variables:**
   ```env
   NODE_ENV=production
   DATABASE_URL=postgresql://user:pass@host:port/db
   JWT_ACCESS_SECRET=your_256_bit_secret_key_here
   JWT_REFRESH_SECRET=different_256_bit_secret_key_here
   JWT_ACCESS_EXPIRES_IN=15m
   JWT_REFRESH_EXPIRES_IN=7d
   BCRYPT_ROUNDS=12
   FRONTEND_URL=https://your-app.netlify.app
   ```

## 🔐 Security Implementation

### JWT Flow & Token Strategy

**Token Types:**
- **Access Token**: Short-lived (15min), stored in memory
- **Refresh Token**: Long-lived (7 days), stored in database with rotation

**Authentication Flow:**
1. User authenticates with email/password
2. Server generates access + refresh token pair
3. Access token used for API requests (Authorization header)
4. When access token expires, refresh token generates new pair
5. Refresh tokens are rotated on each use (security best practice)

### OWASP Vulnerability Mitigation

#### A01:2021 - Broken Access Control
- **JWT Validation**: Every protected route validates tokens server-side
- **Role-Based Permissions**: Middleware enforces USER/ADMIN access levels
- **Resource Ownership**: Users can only access their own data
- **Account Lockout**: 3 failed login attempts = 30-minute lockout

#### A03:2021 - Injection
- **Custom Input Validation**: Email format, password strength, length limits
- **Data Sanitization**: HTML entity encoding for XSS prevention
- **Parameterized Queries**: Prisma ORM prevents SQL injection
- **Input Length Limits**: Prevent buffer overflow attacks

## 📚 API Documentation

### Authentication Endpoints

#### POST `/api/auth/register`
Register new user account with role assignment.

#### POST `/api/auth/login`
Authenticate user and receive token pair with account lockout protection.

#### POST `/api/auth/refresh`
Refresh access token using refresh token with automatic rotation.

#### POST `/api/auth/logout`
Invalidate refresh token and logout user.

### Task Management Endpoints

#### GET `/api/tasks`
**Access:** USER (own tasks), ADMIN (all tasks)

#### POST `/api/tasks`
**Access:** USER, ADMIN

#### PUT `/api/tasks/:id`
**Access:** Task owner, ADMIN

#### DELETE `/api/tasks/:id`
**Access:** ADMIN only

#### POST `/api/tasks/search`
**Access:** USER (own tasks), ADMIN (all tasks)

#### POST `/api/tasks/filter`
**Access:** USER (own tasks), ADMIN (all tasks)

## 🧪 Testing

### Test Accounts (Seeded)
```
Admin: admin@example.com / Admin123!
User:  user@example.com / User123!
```

### Security Testing
1. **Account Lockout**: Try wrong password 3 times
2. **Role Access**: Login as USER, attempt admin operations
3. **Token Expiration**: Wait 15+ minutes, test auto-refresh
4. **Input Validation**: Test XSS payloads, injection attempts

## 📄 License

MIT License - See LICENSE file for details.