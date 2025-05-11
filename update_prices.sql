-- Show current values
SELECT id, name, price FROM subscription_plans ORDER BY id;

-- Update subscription plan prices to NPR values
UPDATE subscription_plans 
SET price = 499
WHERE id = 2;

UPDATE subscription_plans 
SET price = 4000
WHERE id = 3;

-- Verify changes
SELECT id, name, price FROM subscription_plans ORDER BY id; 