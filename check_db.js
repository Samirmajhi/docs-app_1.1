import pg from 'pg';
import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
const envPath = path.resolve(process.cwd(), 'env');
dotenv.config({ path: envPath });

const { Pool } = pg;

// Create a connection pool using environment variables
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: {
    rejectUnauthorized: false
  }
});

async function checkConnection() {
  try {
    console.log('Testing database connection...');
    
    // Test the connection
    const result = await pool.query('SELECT NOW()');
    console.log('Database connection successful!');
    console.log('Server time:', result.rows[0].now);
    
    // Check if users table exists
    const tableResult = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'users'
      );
    `);
    
    console.log('Users table exists:', tableResult.rows[0].exists);
    
  } catch (error) {
    console.error('Database connection error:', error);
  } finally {
    await pool.end();
  }
}

checkConnection(); 