import winston from 'winston';
import 'winston-daily-rotate-file';
import path from 'path';
import config from '../config/production.js';

const { logging } = config;

// Create logs directory if it doesn't exist
const fs = require('fs');
if (!fs.existsSync(logging.filePath)) {
  fs.mkdirSync(logging.filePath, { recursive: true });
}

// Define log format
const logFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Create the logger
const logger = winston.createLogger({
  level: logging.level,
  format: logFormat,
  transports: [
    // Write all logs to console in development
    ...(process.env.NODE_ENV !== 'production' ? [
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        )
      })
    ] : []),
    // Write all logs to rotating files
    new winston.transports.DailyRotateFile({
      filename: path.join(logging.filePath, 'combined-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: logging.maxSize,
      maxFiles: logging.maxFiles
    }),
    // Write all errors to error log
    new winston.transports.DailyRotateFile({
      filename: path.join(logging.filePath, 'error-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: logging.maxSize,
      maxFiles: logging.maxFiles,
      level: 'error'
    })
  ]
});

// Create a stream object for Morgan
const stream = {
  write: (message) => {
    logger.info(message.trim());
  }
};

export { logger, stream }; 