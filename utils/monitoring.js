import client from 'prom-client';
import { logger } from './logger.js';
import config from '../config/production.js';

const { monitoring } = config;

// Create a Registry
const register = new client.Registry();

// Add default metrics
client.collectDefaultMetrics({ register });

// Custom metrics
const httpRequestDuration = new client.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 0.5, 1, 2, 5]
});

const activeUsers = new client.Gauge({
  name: 'active_users',
  help: 'Number of active users'
});

const documentUploads = new client.Counter({
  name: 'document_uploads_total',
  help: 'Total number of document uploads',
  labelNames: ['status']
});

const accessRequests = new client.Counter({
  name: 'access_requests_total',
  help: 'Total number of access requests',
  labelNames: ['status']
});

// Register custom metrics
register.registerMetric(httpRequestDuration);
register.registerMetric(activeUsers);
register.registerMetric(documentUploads);
register.registerMetric(accessRequests);

// Middleware to track request duration
const trackRequestDuration = (req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    httpRequestDuration
      .labels(req.method, req.route?.path || req.path, res.statusCode.toString())
      .observe(duration);
  });
  next();
};

// Middleware to track active users
const trackActiveUsers = (req, res, next) => {
  if (req.user) {
    activeUsers.inc();
  }
  res.on('finish', () => {
    if (req.user) {
      activeUsers.dec();
    }
  });
  next();
};

// Health check function
const healthCheck = async () => {
  try {
    // Add your health check logic here
    // For example, check database connection, cache connection, etc.
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage()
    };
  } catch (error) {
    logger.error('Health check failed:', error);
    return {
      status: 'unhealthy',
      error: error.message
    };
  }
};

export {
  register,
  trackRequestDuration,
  trackActiveUsers,
  healthCheck,
  documentUploads,
  accessRequests
}; 