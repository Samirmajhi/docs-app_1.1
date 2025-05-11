
# SecureDoc - Local Development Guide

This guide will help you set up and run the SecureDoc application locally.

## Prerequisites

- Node.js (v14 or newer)
- PostgreSQL database
- Git

## Backend Setup

1. First, make sure PostgreSQL is installed and running.

2. Create a database and user:
```sql
CREATE DATABASE securedoc;
CREATE USER securedocuser WITH ENCRYPTED PASSWORD 'your-secure-password';
GRANT ALL PRIVILEGES ON DATABASE securedoc TO securedocuser;
```

3. Clone the repository:
```bash
git clone https://github.com/yourusername/securedoc.git
cd securedoc
```

4. Install backend dependencies:
```bash
npm install
```

5. Start the backend server:
```bash
node server.js
```

The server should now be running on http://localhost:3000.

## Frontend Setup

1. In a new terminal, navigate to the project directory.

2. Install frontend dependencies:
```bash
npm install
```

3. Start the frontend development server:
```bash
npm run dev
```

The frontend should now be accessible at http://localhost:5173 (or another port if 5173 is in use).

## Configuration

Make sure your `.env` file contains the following:

```
# API Settings
VITE_API_URL=http://localhost:3000/api
VITE_STORAGE_URL=http://localhost:3000/storage

# Auth Settings
VITE_JWT_SECRET=your-secret-key

# Database settings
VITE_DB_HOST=localhost
VITE_DB_PORT=5432
VITE_DB_NAME=securedoc
VITE_DB_USER=securedocuser
VITE_DB_PASSWORD=your-secure-password
```

## Testing Authentication

1. Register a new account at http://localhost:5173/
2. Login with your credentials
3. You should be redirected to the dashboard

## Testing Document Upload

1. Go to http://localhost:5173/documents
2. Click "Upload Document"
3. Select a file and upload it
4. You should see the document appear in the list

## Testing QR Code Generation

1. Go to http://localhost:5173/share
2. Enter an optional access code
3. Click "Generate QR Code"
4. You should see the QR code displayed

## Troubleshooting

- If you see "Using mock data for:" in the console, it means the frontend is falling back to mock data because the backend is not accessible. Make sure your backend server is running and the VITE_API_URL is set correctly.
- If you encounter database connection errors, check your PostgreSQL settings and make sure the credentials in your .env file are correct.
- For document upload issues, check that the uploads directory exists and has the correct permissions.
