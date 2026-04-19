# 🔐 AuthSystem

A modern, multi-factor authentication system demonstrating secure user authentication with support for passwords, time-based one-time passwords (TOTP), and passkeys (WebAuthn). Built as a comprehensive reference implementation for authentication best practices.

## 🚀 Live Demo

**[Try the live demo here](https://auth-system-jr80.onrender.com)** 

> **Note**: The demo is hosted on Render.com's free tier and may take 30-60 seconds to wake up on first access after inactivity.

### Demo Credentials
You can register your own account or use these test accounts:
- **Username**: `demo_member` | **Password**: `demo123` (Member role)
- **Username**: `demo_staff` | **Password**: `demo123` (Community Staff role)

### What to Try
1. 🔐 **Register** a new account with any of the three subject types
2. 🔑 **Login** with password authentication
3. 📱 **Set up OTP** using Google Authenticator or Authy
4. 🎯 **Enable MFA** to require both password + OTP
5. 🔒 **Register a Passkey** for passwordless login (requires HTTPS)
6. 📊 **View Sessions** and manage multi-device logins
7. 🚪 **Logout** from individual devices or all at once

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

### SOLID Principles Implementation

The authentication system follows SOLID design principles for maintainability and extensibility:

#### Single Responsibility Principle
- **AuthService**: Orchestrates authentication flows and manages authenticators
- **SessionManager**: Handles all session lifecycle operations
- **Authenticator classes**: Each authentication method (Password, OTP) is isolated
- **SubjectPolicy**: Manages role-based permissions separately

#### Open/Closed Principle
- New authentication methods can be added by creating new `Authenticator` implementations
- No changes needed to routes or `AuthService` when adding new login methods
- Example: Adding OAuth would only require creating `OAuthAuthenticator.js` and registering it

#### Dependency Inversion Principle
- Routes depend on `AuthService` abstraction, not concrete implementations
- Authenticators implement a common interface defined in `Authenticator.js`
- Easy to swap storage backends (e.g., Redis) by changing only `SessionManager`

### Architecture Benefits
- **Extensible**: Add new authentication methods without modifying existing code
- **Testable**: Each component can be tested in isolation with mocks
- **Maintainable**: Clear separation of concerns makes debugging easier
- **Type-safe**: Typed error classes (`AuthError`, `TokenError`) for precise error handling

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
│   ├── auth/                 # Authentication core (SOLID architecture)
│   │   ├── AuthService.js    # Central authentication orchestrator
│   │   ├── Authenticator.js  # Base authenticator interface
│   │   ├── PasswordAuthenticator.js # Password authentication strategy
│   │   ├── OtpAuthenticator.js      # TOTP authentication strategy
│   │   ├── SessionManager.js        # Session lifecycle management
│   │   ├── SubjectPolicy.js         # Role-based access control policies
│   │   └── ChallengeStore.js        # WebAuthn challenge management
│   ├── db/
│   │   ├── database.js       # Database initialization and persistence
│   │   └── models.js         # Data access layer (CRUD operations)
│   ├── routes/
│   │   ├── auth.js           # Authentication routes (delegates to AuthService)
│   │   ├── passkey.js        # WebAuthn passkey routes
│   │   └── passkey-helpers.js # Device parsing utilities
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

#### Unit Tests (Backend API)

```bash
npm test
```

The test suite includes:
- Unit tests for authentication flows
- Session management tests
- OTP setup and verification tests
- Passkey registration and authentication tests
- Edge case and error handling tests

**Test Coverage**: 172 tests covering all API endpoints and edge cases

#### UI/E2E Tests (Frontend)

```bash
# Run all UI tests (headless)
npm run test:ui

# Run with visible browser
npm run test:ui:headed

# Debug tests with Playwright Inspector
npm run test:ui:debug
```

The UI test suite includes:
- **Registration flows** - Form validation, successful registration, duplicate handling
- **Login flows** - Credential validation, error handling, dashboard navigation
- **Dashboard** - Profile display, session management, logout functionality
- **OTP setup** - QR code display, code validation, enable/disable flows
- **Session management** - Multi-device sessions, revocation, logout-all

**UI Test Coverage**: 28 end-to-end tests across 4 test suites

For more details on UI testing, see [e2e/README.md](e2e/README.md).

## 🧪 Testing Strategy

This project includes comprehensive testing at multiple levels:

### Test Pyramid

```
        /\
       /UI\         28 E2E tests (Playwright)
      /----\
     /Unit  \       172 API tests (Jest + Supertest)
    /--------\
   /Integration\    Full stack coverage
  /--------------\
```

### Backend Tests (Jest + Supertest)
- **172 tests** covering all API endpoints
- **91%+ code coverage**
- Tests run against real SQLite database
- Isolated test data with unique identifiers
- Mock-free for integration testing authenticity

### Frontend Tests (Playwright)
- **28 E2E tests** simulating real user interactions
- Tests run in Chromium browser
- Auto-starts server before test execution
- Screenshots on failure for debugging
- Sequential execution to avoid database conflicts

### Test Organization

```
tests/                          # Backend unit/integration tests
├── auth.test.js               # Core authentication
├── auth-session.test.js       # Session management
├── auth-edge-cases.test.js    # Error handling
├── otp.test.js                # OTP flows
├── passkey.test.js            # Passkey basics
├── passkey-success.test.js    # Passkey success paths
├── passkey-edge-cases.test.js # Passkey error handling
└── server.test.js             # Static file serving

e2e/                           # Frontend E2E tests
├── auth-registration.spec.js  # Registration flows
├── auth-login.spec.js         # Login flows
├── dashboard.spec.js          # Dashboard interactions
└── otp.spec.js                # OTP UI flows
```

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

## 🚀 Deployment

### Deploy to Render.com (Free)

1. Fork this repository to your GitHub account

2. Sign up at [Render.com](https://render.com)

3. Create a new Web Service:
   - Connect your GitHub repository
   - Select the `auth-system` repository
   - Render will auto-detect the `render.yaml` configuration
   - Click "Create Web Service"

4. Your app will be deployed at `https://your-app-name.onrender.com`

**Note**: Free tier services spin down after 15 minutes of inactivity and take 30-60 seconds to wake up.

### Deploy to Other Platforms

#### Heroku
```bash
heroku create your-app-name
git push heroku main
```

#### Railway
```bash
railway init
railway up
```

#### Vercel (Serverless)
```bash
vercel --prod
```

### Environment Variables for Production

Set these in your hosting platform:
- `NODE_ENV=production`
- `PORT` (usually auto-set by platform)
- `WEBAUTHN_RP_ID` (your domain, e.g., `your-app.onrender.com`)
- `WEBAUTHN_ORIGIN` (full URL, e.g., `https://your-app.onrender.com`)

## License

This project is licensed under the ISC License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Acknowledgments

- Built with [@simplewebauthn](https://github.com/MasterKale/SimpleWebAuthn) for WebAuthn implementation
- Uses [speakeasy](https://github.com/speakeasyjs/speakeasy) for TOTP generation
- Inspired by modern authentication best practices and standards
