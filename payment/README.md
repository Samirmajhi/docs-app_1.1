# eSewa Payment Integration

This is a Node.js project that demonstrates how to integrate eSewa payment gateway into your application.

## Prerequisites

- Node.js (v12 or higher)
- npm (Node Package Manager)
- eSewa merchant account

## Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create a `.env` file in the root directory with the following variables:
   ```
   PORT=3000
   ESEWA_MERCHANT_ID=your_merchant_id_here
   SUCCESS_URL=http://localhost:3000/payment-success
   FAILURE_URL=http://localhost:3000/payment-failure
   ```
4. Replace `your_merchant_id_here` with your actual eSewa merchant ID

## Running the Application

Development mode:
```bash
npm run dev
```

Production mode:
```bash
npm start
```

The application will be available at `http://localhost:3000`

## Features

- Simple payment form interface
- eSewa payment integration
- Success and failure callback handling
- Environment variable configuration

## Important Notes

1. This is a basic implementation and should be enhanced with proper security measures in production
2. Always verify payments on the server side
3. Use HTTPS in production
4. Implement proper error handling and logging
5. Store transaction details in a database

## Testing

For testing purposes, you can use eSewa's test credentials. In production, make sure to use your actual merchant credentials and implement proper security measures. 