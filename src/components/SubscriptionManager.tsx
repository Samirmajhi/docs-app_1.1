import React, { useEffect, useState } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { toast } from 'react-hot-toast';
import subscriptionService, { SubscriptionPlan } from '@/services/subscription.service';

const formatStorage = (bytes: number): string => {
  const mb = bytes / (1024 * 1024);
  return `${mb.toFixed(1)} MB`;
};

const SubscriptionManager: React.FC = () => {
  const [plans, setPlans] = useState<SubscriptionPlan[]>([]);
  const [currentPlan, setCurrentPlan] = useState<SubscriptionPlan | null>(null);
  const [storageUsage, setStorageUsage] = useState<{ used: number; limit: number } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [plansData, currentPlanData, storageData] = await Promise.all([
          subscriptionService.getPlans(),
          subscriptionService.getCurrentSubscription(),
          subscriptionService.getStorageUsage()
        ]);

        setPlans(plansData);
        setCurrentPlan(currentPlanData);
        setStorageUsage(storageData);
      } catch (error) {
        toast.error('Failed to load subscription data');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const handlePlanChange = async (planId: number) => {
    try {
      await subscriptionService.updateSubscription(planId);
      const updatedPlan = plans.find(plan => plan.id === planId);
      setCurrentPlan(updatedPlan || null);
      toast.success('Subscription updated successfully');
    } catch (error) {
      toast.error('Failed to update subscription');
    }
  };

  if (loading) {
    return <div>Loading subscription data...</div>;
  }

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Current Plan Section */}
      {currentPlan && (
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Current Plan: {currentPlan.name}</CardTitle>
            <CardDescription>
              {currentPlan.price === 0 ? 'Free Plan' : `$${currentPlan.price}/month`}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {storageUsage && (
              <div className="space-y-4">
                <div className="flex justify-between text-sm">
                  <span>Storage Usage</span>
                  <span>{formatStorage(storageUsage.used)} / {formatStorage(storageUsage.limit)}</span>
                </div>
                <Progress value={(storageUsage.used / storageUsage.limit) * 100} />
              </div>
            )}
            <div className="mt-4">
              <h4 className="font-semibold mb-2">Features:</h4>
              <ul className="space-y-2">
                {currentPlan.features.map((feature, index) => (
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
            </div>
          </CardContent>
        </Card>
      )}

      {/* Available Plans Section */}
      <h2 className="text-2xl font-bold mb-6">Available Plans</h2>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {plans.map((plan) => (
          <Card key={plan.id} className="flex flex-col">
            <CardHeader>
              <CardTitle>{plan.name}</CardTitle>
              <CardDescription>
                {plan.price === 0 ? 'Free' : `$${plan.price}/month`}
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
                variant={currentPlan?.id === plan.id ? "outline" : "default"}
                onClick={() => handlePlanChange(plan.id)}
                disabled={currentPlan?.id === plan.id}
              >
                {currentPlan?.id === plan.id ? 'Current Plan' : 'Select Plan'}
              </Button>
            </CardFooter>
          </Card>
        ))}
      </div>
    </div>
  );
};

export default SubscriptionManager; 