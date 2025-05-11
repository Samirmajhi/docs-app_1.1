import pg from 'pg';
import fs from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';

const { Pool } = pg;

// Create a connection pool
const pool = new Pool({
  connectionString: 'postgresql://neondb_owner:npg_8fWqJMv4Ksel@ep-square-snowflake-a4gn24ow-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require',
  ssl: {
    rejectUnauthorized: false
  }
});

// Read SQL file
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const sqlFileName = process.argv[2];

if (!sqlFileName) {
  console.error('Please provide an SQL file name as an argument');
  process.exit(1);
}

const sql = fs.readFileSync(path.join(__dirname, sqlFileName), 'utf8');

// Function to run SQL
async function runSQL() {
  try {
    // First, let's check what type the document.id column is
    const schemaResult = await pool.query(`
      SELECT column_name, data_type, udt_name
      FROM information_schema.columns 
      WHERE table_name = 'documents' AND column_name = 'id'
    `);
    
    console.log('Documents table id column info:', JSON.stringify(schemaResult.rows, null, 2));
    
    // Split the SQL into separate queries
    const queries = sql.split(';').filter(query => query.trim() !== '');
    
    for (const query of queries) {
      const trimmedQuery = query.trim();
      if (trimmedQuery) {
        const result = await pool.query(trimmedQuery);
        
        // If this is a SELECT query, display the results
        if (trimmedQuery.toLowerCase().startsWith('select')) {
          console.log(`Results for query: ${trimmedQuery}`);
          console.table(result.rows);
        }
      }
    }
    
    console.log('SQL script executed successfully!');
    
  } catch (error) {
    console.error('Error executing SQL:', error);
  } finally {
    pool.end();
  }
}

runSQL(); 