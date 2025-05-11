import pg from 'pg';

const { Pool } = pg;

// Create a connection pool
const pool = new Pool({
  connectionString: 'postgresql://neondb_owner:npg_8fWqJMv4Ksel@ep-square-snowflake-a4gn24ow-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require',
  ssl: {
    rejectUnauthorized: false
  }
});

async function checkPrices() {
  try {
    console.log('Checking subscription plans...');
    
    // Query current subscription plans
    const plansResult = await pool.query('SELECT id, name, price, storage_limit FROM subscription_plans ORDER BY id');
    
    console.log('Current subscription plans:');
    console.log(plansResult.rows);
    
    // Update prices directly
    console.log('Updating Pro plan price to 499...');
    await pool.query('UPDATE subscription_plans SET price = 499 WHERE id = 2');
    
    console.log('Updating Enterprise plan price to 4000...');
    await pool.query('UPDATE subscription_plans SET price = 4000 WHERE id = 3');
    
    // Check updated plans
    const updatedPlansResult = await pool.query('SELECT id, name, price, storage_limit FROM subscription_plans ORDER BY id');
    
    console.log('Updated subscription plans:');
    console.log(updatedPlansResult.rows);
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await pool.end();
  }
}

checkPrices(); 