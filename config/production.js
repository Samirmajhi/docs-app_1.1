import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load production environment variables
dotenv.config({ path: path.resolve(__dirname, '../.env.production') });

export default {
  // Server Configuration
  server: {
    port: process.env.PORT || 8000,
    host: process.env.HOST || '0.0.0.0',
    env: process.env.NODE_ENV || 'production',
    cors: {
      origin: process.env.CORS_ORIGIN?.split(',') || ['https://yourdomain.com'],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
      exposedHeaders: ['Content-Range', 'X-Content-Range'],
      maxAge: 600
    }
  },

  // Database Configuration
  database: {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
    max: 20, // Maximum number of clients in the pool
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
  },

  // Security Configuration
  security: {
    jwtSecret: process.env.JWT_SECRET,
    jwtExpiresIn: '24h',
    rateLimit: {
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000, // 15 minutes
      max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
      message: 'Too many requests from this IP, please try again later.'
    },
    bcryptSaltRounds: 10,
    allowedFileTypes: ['application/pdf', 'image/jpeg', 'image/png', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    maxFileSize: 10 * 1024 * 1024, // 10MB
  },

  // Email Configuration
  email: {
    user: process.env.EMAIL_USER,
    appPassword: process.env.EMAIL_APP_PASSWORD,
    from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
    templates: {
      accessRequest: path.resolve(__dirname, '../templates/email/access-request.html'),
      approval: path.resolve(__dirname, '../templates/email/approval.html'),
      denial: path.resolve(__dirname, '../templates/email/denial.html')
    }
  },

  // Storage Configuration
  storage: {
    uploadDir: path.resolve(__dirname, '../uploads'),
    tempDir: path.resolve(__dirname, '../temp'),
    maxFileSize: 10 * 1024 * 1024, // 10MB
    allowedMimeTypes: [
      'application/pdf',
      'image/jpeg',
      'image/png',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ]
  },

  // Logging Configuration
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    filePath: process.env.LOG_FILE_PATH || path.resolve(__dirname, '../logs'),
    maxFiles: '14d',
    maxSize: '20m',
    format: 'combined'
  },

  // Cache Configuration
  cache: {
    enabled: process.env.CACHE_ENABLED === 'true',
    ttl: 3600, // 1 hour
    checkperiod: 600 // 10 minutes
  },

  // Monitoring Configuration
  monitoring: {
    enabled: process.env.MONITORING_ENABLED === 'true',
    metricsPath: '/metrics',
    healthCheckPath: '/health',
    prometheusEnabled: process.env.PROMETHEUS_ENABLED === 'true'
  },

  // Frontend Configuration
  frontend: {
    url: process.env.FRONTEND_URL,
    apiUrl: process.env.VITE_API_URL,
    storageUrl: process.env.VITE_STORAGE_URL
  }
}; 