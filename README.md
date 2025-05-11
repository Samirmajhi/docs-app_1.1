# SecureDoc - Secure Document Sharing Platform

SecureDoc is a secure document management and sharing platform that allows users to safely store, manage, and share their important documents with others through QR codes.

## Features

- **Secure Document Storage**: Upload and manage your sensitive documents securely
- **QR Code Sharing**: Generate QR codes to share specific documents with others
- **Optional Access Code**: Add an extra layer of security with access codes for your QR codes
- **Document Format Conversion**: Download documents in various formats (PDF, DOCX, TXT, JPG)
- **Access Management**: Control who can access your documents and for how long
- **Mobile Verification**: Verify document owners through mobile number and PIN

## Technology Stack

- **Frontend**: React, TypeScript, Tailwind CSS, Shadcn UI
- **Backend**: Node.js, Express.js
- **Database**: PostgreSQL
- **Authentication**: JWT (JSON Web Tokens)
- **File Storage**: Server-side file system storage

## Getting Started

### Prerequisites

- Node.js (v16+)
- PostgreSQL (v13+)

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/securedoc.git
   cd securedoc
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Set up environment variables:
   - Create a `.env` file in the root directory
   - Add the following variables:
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

4. Start the backend server:
   ```
   npm run server
   ```

5. Start the frontend development server:
   ```
   npm run dev
   ```

### Production Deployment

For production deployment:

1. Build the frontend:
   ```
   npm run build
   ```

2. Configure your production environment variables
   
3. Deploy the backend server
   
4. Set up a web server (Nginx/Apache) to serve the frontend build files

## Security Features

- JWT-based authentication
- Secure document storage
- Optional access codes for QR codes
- Mobile verification for document owners
- Limited-time access to shared documents
- Document access logging

## Payment Integration

This application now includes integration with the eSewa payment gateway for subscription payments. Key features include:

- Secure payment processing through eSewa
- Support for subscription plan upgrades
- Payment verification and subscription management
- Transaction history tracking

### Payment Configuration

To configure the payment gateway:

1. Update the eSewa credentials in the `server.js` file:
   ```javascript
   const ESEWA_SECRET_KEY = "your_secret_key_here";
   const ESEWA_GATEWAY_URL = "https://rc-epay.esewa.com.np"; // or production URL
   const ESEWA_PRODUCT_CODE = "your_product_code_here";
   ```

2. Ensure the database includes the payment_transactions table (run the SQL in temp_fix.sql)

3. Update the success and failure URLs in the payment service if needed.

### Testing Payments

For testing the payment integration, you can use eSewa's test credentials or sandbox environment. In production, make sure to change the gateway URL and use your actual merchant credentials.

## License

This project is licensed under the MIT License - see the LICENSE file for details.