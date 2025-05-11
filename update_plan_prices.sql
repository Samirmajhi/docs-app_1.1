-- Update subscription plan prices to NPR values
UPDATE subscription_plans 
SET price = '499' 
WHERE id = 2 AND name = 'Pro';

UPDATE subscription_plans 
SET price = '4000' 
WHERE id = 3 AND name = 'Enterprise';

-- Verify changes
SELECT id, name, price FROM subscription_plans ORDER BY id; 