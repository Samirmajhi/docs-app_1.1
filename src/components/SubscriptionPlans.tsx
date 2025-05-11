import React, { useEffect, useState } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import subscriptionService, { SubscriptionPlan } from '@/services/subscription.service';
import { toast } from 'react-hot-toast';

interface SubscriptionPlansProps {
  onPlanSelect?: (planId: number) => void;
  showStorageUsage?: boolean;
}

const formatStorage = (bytes: number): string => {
  const mb = bytes / (1024 * 1024);
  return `${mb.toFixed(1)} MB`;
};

const SubscriptionPlans: React.FC<SubscriptionPlansProps> = ({ onPlanSelect, showStorageUsage = false }) => {
  const [plans, setPlans] = useState<SubscriptionPlan[]>([]);
  const [loading, setLoading] = useState(true);
  const [storageUsage, setStorageUsage] = useState<{ used: number; limit: number } | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const plansData = await subscriptionService.getPlans();
        setPlans(plansData);
        
        if (showStorageUsage) {
          const usage = await subscriptionService.getStorageUsage();
          setStorageUsage(usage);
        }
      } catch (error) {
        toast.error('Failed to load subscription plans');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [showStorageUsage]);

  const handlePlanSelect = async (planId: number) => {
    try {
      await subscriptionService.updateSubscription(planId);
      toast.success('Subscription updated successfully');
      if (onPlanSelect) {
        onPlanSelect(planId);
      }
    } catch (error) {
      toast.error('Failed to update subscription');
    }
  };

  if (loading) {
    return <div>Loading plans...</div>;
  }

  return (
    <div className="container mx-auto px-4 py-8">
      {showStorageUsage && storageUsage && (
        <div className="mb-8">
          <h3 className="text-lg font-semibold mb-2">Storage Usage</h3>
          <div className="flex items-center gap-4">
            <Progress value={(storageUsage.used / storageUsage.limit) * 100} className="flex-1" />
            <span className="text-sm text-gray-600">
              {formatStorage(storageUsage.used)} / {formatStorage(storageUsage.limit)}
            </span>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {plans.map((plan) => (
          <Card key={plan.id} className="flex flex-col">
            <CardHeader>
              <CardTitle>{plan.name}</CardTitle>
              <CardDescription>
                {plan.price === 0 ? 'Free' : `NPR ${plan.price.toLocaleString()}/month`}
              </CardDescription>
            </CardHeader>
            <CardContent className="flex-grow">
              <ul className="space-y-2">
                {plan.features.map((feature, index) => (
                  <li key={index} className="flex items-center">
                    <svg
                      className="w-4 h-4 mr-2 text-green-500"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                    {feature}
                  </li>
                ))}
              </ul>
              <div className="mt-4">
                <p className="text-sm text-gray-600">
                  Storage: {formatStorage(plan.storage_limit)}
                </p>
              </div>
            </CardContent>
            <CardFooter>
              <Button
                className="w-full"
                onClick={() => handlePlanSelect(plan.id)}
              >
                Select Plan
              </Button>
            </CardFooter>
          </Card>
        ))}
      </div>
    </div>
  );
};

export default SubscriptionPlans; 