# 🔐 AuthSystem

A modern, multi-factor authentication system demonstrating secure user authentication with support for passwords, time-based one-time passwords (TOTP), and passkeys (WebAuthn). Built as a comprehensive reference implementation for authentication best practices.

## What is this project?

AuthSystem is a full-stack authentication demo that showcases multiple authentication methods and session management patterns. It implements a role-based access control system with three subject types (Member, Community Staff, Platform Staff) and provides a complete authentication flow from registration to session management.

This project serves as both a learning resource and a foundation for building secure authentication systems in Node.js applications.

## Features

### Authentication Methods
- **Password Authentication**: Traditional username/password login with bcrypt hashing
- **OTP (TOTP)**: Time-based one-time passwords using authenticator apps (Google Authenticator, Authy, etc.)
- **Passkeys (WebAuthn)**: Passwordless authentication using biometrics or security keys
- **Multi-Factor Authentication (MFA)**: Optional OTP layer on top of password authentication

### Session Management
- Secure session tokens with configurable expiration (7-day default)
- Multi-device session tracking with device fingerprinting
- View and revoke individual sessions
- Logout from all devices functionality
- Automatic session cleanup and expiration handling

### User Management
- User registration with subject type assignment
- Account recovery and OTP reset functionality
- Profile information with authentication method status
- Support for multiple authentication methods per user

### Security Features
- Password hashing with bcrypt (10 rounds)
- TOTP secret generation and QR code provisioning
- WebAuthn challenge-response authentication
- Session token validation middleware
- Temporary token system for multi-step flows
- Foreign key constraints and data integrity

## Technical Architecture

### Backend Stack
- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: sql.js (SQLite in-memory with file persistence)
- **Authentication Libraries**:
  - `bcryptjs` - Password hashing
  - `speakeasy` - TOTP generation and verification
  - `@simplewebauthn/server` - WebAuthn server-side implementation
  - `qrcode` - QR code generation for OTP setup

### Frontend Stack
- Vanilla JavaScript (no framework dependencies)
- `@simplewebauthn/browser` - WebAuthn client-side implementation
- Responsive CSS with modern UI patterns

### Database Schema

```
subjects
├── id (INTEGER PRIMARY KEY)
├── type (TEXT: 'member' | 'community_staff' | 'platform_staff')
└── name (TEXT)

users
├── id (INTEGER PRIMARY KEY AUTOINCREMENT)
├── subject_id (INTEGER → subjects.id)
├── username (TEXT UNIQUE)
├── password_hash (TEXT)
├── otp_secret (TEXT, nullable)
├── passkey_credential_id (TEXT, nullable)
├── passkey_public_key (TEXT, nullable)
└── created_at (INTEGER timestamp)

sessions
├── id (TEXT PRIMARY KEY, UUID)
├── user_id (INTEGER → users.id)
├── device_name (TEXT)
├── ip_address (TEXT)
├── created_at (INTEGER timestamp)
├── expires_at (INTEGER timestamp)
└── last_active_at (INTEGER timestamp)

temp_tokens
├── token (TEXT PRIMARY KEY, UUID)
├── user_id (INTEGER → users.id)
├── type (TEXT: 'mfa_init' | 'otp_setup_pending')
├── data (TEXT, nullable)
├── created_at (INTEGER timestamp)
└── expires_at (INTEGER timestamp)
```

### Project Structure

```
auth-system/
├── server.js                 # Express app setup and entry point
├── package.json              # Dependencies and scripts
├── src/
│   ├── db/
│   │   ├── database.js       # Database initialization and persistence
│   │   └── models.js         # Data access layer (CRUD operations)
│   ├── routes/
│   │   ├── auth.js           # Password and OTP authentication routes
│   │   ├── passkey.js        # WebAuthn passkey routes
│   │   ├── passkey-helpers.js # Device parsing utilities
│   │   └── otpHelpers.js     # OTP utility functions
│   └── middleware/
│       └── auth.js           # Session validation middleware
├── public/
│   ├── index.html            # Login page
│   ├── register.html         # Registration page
│   ├── dashboard.html        # User dashboard (session management, OTP/passkey setup)
│   ├── recover.html          # Account recovery page
│   ├── style.css             # Application styles
│   └── lib/
│       └── simplewebauthn-browser.umd.min.js
├── tests/                    # Comprehensive test suite
│   ├── auth.test.js
│   ├── auth-session.test.js
│   ├── auth-edge-cases.test.js
│   ├── otp.test.js
│   ├── passkey.test.js
│   ├── passkey-success.test.js
│   ├── passkey-edge-cases.test.js
│   ├── passkey-credential-structure.test.js
│   ├── passkey-helpers.test.js
│   └── server.test.js
└── data/
    └── auth.db               # SQLite database file (created on first run)
```

## How to Build It

### Prerequisites
- Node.js 16+ and npm

### Installation

1. Clone the repository:
```bash
git clone https://github.com/ChunkyBoy-USA/auth-system.git
cd auth-system
```

2. Install dependencies:
```bash
npm install
```

### Running the Application

#### Development Mode (with auto-reload)
```bash
npm run dev
```

#### Production Mode
```bash
npm start
```

The server will start on `http://localhost:3000` by default.

### Environment Variables

Optional configuration via environment variables:

- `PORT` - Server port (default: 3000)
- `HOST` - Server host (default: 0.0.0.0)
- `WEBAUTHN_RP_ID` - WebAuthn Relying Party ID (default: derived from request origin)
- `WEBAUTHN_ORIGIN` - WebAuthn origin for verification (default: http://localhost:PORT)

### Testing Cross-Device Passkeys

To test passkeys across devices (e.g., phone to computer):

1. Find your local IP address:
```bash
# macOS/Linux
ifconfig | grep "inet "
# Windows
ipconfig
```

2. Set the HOST environment variable and start the server:
```bash
HOST=192.168.x.x npm start
```

3. Access the application from your phone at `http://192.168.x.x:3000`

### Running Tests

```bash
npm test
```

The test suite includes:
- Unit tests for authentication flows
- Session management tests
- OTP setup and verification tests
- Passkey registration and authentication tests
- Edge case and error handling tests

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login/password` - Login with password
- `POST /api/auth/login/otp` - Login with OTP code
- `POST /api/auth/logout` - Logout current session
- `POST /api/auth/logout-all` - Logout all sessions
- `GET /api/auth/me` - Get current user info
- `GET /api/auth/sessions` - List all user sessions
- `DELETE /api/auth/sessions/:id` - Revoke specific session

### Multi-Factor Authentication
- `POST /api/auth/mfa/init` - Initialize MFA flow (password verification)
- `POST /api/auth/mfa/verify` - Complete MFA flow (OTP verification)

### OTP Management
- `POST /api/auth/otp/setup` - Generate OTP secret and QR code
- `POST /api/auth/otp/enable` - Enable OTP after verification
- `POST /api/auth/otp/disable` - Disable OTP (requires OTP code)

### Passkey Management
- `POST /api/auth/passkey/register-options` - Get WebAuthn registration options
- `POST /api/auth/passkey/register-verify` - Verify and save passkey
- `POST /api/auth/passkey/login-options` - Get WebAuthn authentication options
- `POST /api/auth/passkey/login-verify` - Verify passkey and create session

### Account Recovery
- `POST /api/auth/recover/reset-otp` - Reset OTP with password

## Usage Examples

### Registering a User

```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "secure-password-123",
    "subjectId": 1
  }'
```

### Password Login

```bash
curl -X POST http://localhost:3000/api/auth/login/password \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "secure-password-123"
  }'
```

### Setting Up OTP

1. Setup (requires authentication token):
```bash
curl -X POST http://localhost:3000/api/auth/otp/setup \
  -H "Authorization: Bearer <session-token>" \
  -H "Content-Type: application/json"
```

2. Enable with verification code:
```bash
curl -X POST http://localhost:3000/api/auth/otp/enable \
  -H "Authorization: Bearer <session-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "otp_code": "123456",
    "setupToken": "<setup-token-from-previous-step>"
  }'
```

## Security Considerations

- Passwords are hashed using bcrypt with 10 rounds
- Sessions expire after 7 days of inactivity
- OTP secrets are stored securely and never exposed after initial setup
- WebAuthn challenges are single-use and expire after 5 minutes
- Temporary tokens for multi-step flows expire after 5-10 minutes
- Database uses foreign key constraints to maintain referential integrity
- All authentication endpoints validate input and return appropriate error codes

## Development Notes

- The database is persisted to `data/auth.db` and survives server restarts
- In-memory SQLite provides fast performance for development and testing
- For production use, consider migrating to PostgreSQL or MySQL
- WebAuthn requires HTTPS in production (localhost works for development)
- TOTP codes are valid for 30 seconds with a standard time window

## License

This project is licensed under the ISC License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Acknowledgments

- Built with [@simplewebauthn](https://github.com/MasterKale/SimpleWebAuthn) for WebAuthn implementation
- Uses [speakeasy](https://github.com/speakeasyjs/speakeasy) for TOTP generation
- Inspired by modern authentication best practices and standards
