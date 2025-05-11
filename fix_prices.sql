-- Show current values
SELECT id, name, price, storage_limit FROM subscription_plans;

-- Directly update prices without condition (since we know the IDs)
UPDATE subscription_plans SET price = 499 WHERE id = 2;
UPDATE subscription_plans SET price = 4000 WHERE id = 3;

-- Verify the changes
SELECT id, name, price, storage_limit FROM subscription_plans; 