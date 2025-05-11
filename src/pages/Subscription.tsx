import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useLocation } from 'react-router-dom';
import { toast } from 'sonner';
import { ArrowLeft, Check, Crown, Database, Shield, Clock, Users, ChevronRight } from 'lucide-react';

import Navbar from '@/components/layout/Navbar';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/context/AuthContext';
import subscriptionService from '@/services/subscription.service';
import { Switch } from '@/components/ui/switch';
import { Card, CardContent } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { motion } from 'framer-motion';
import eventBus from '@/utils/eventBus';

// Helper function to format storage size
const formatStorage = (bytes: number): string => {
  if (bytes === 0) return 'Unlimited';
  const mb = bytes / (1024 * 1024);
  return `${mb.toFixed(1)} MB`;
};

const Subscription = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();
  
  // Business/Personal toggle
  const [isBusinessPlan, setIsBusinessPlan] = useState(false);
  // Payment status
  const [isProcessingPayment, setIsProcessingPayment] = useState(false);
  
  // Check for payment status in URL (returned from payment gateway)
  useEffect(() => {
    const searchParams = new URLSearchParams(location.search);
    const data = searchParams.get('data');
    
    if (data) {
      // This means we're returning from eSewa payment
      handlePaymentVerification(data);
    }
  }, [location]);

  // Handle payment verification
  const handlePaymentVerification = async (data: string) => {
    try {
      setIsProcessingPayment(true);
      await subscriptionService.verifyPayment(data);
      toast.success('Payment successful! Your subscription has been updated.');
      queryClient.invalidateQueries({ queryKey: ['subscription'] });
      queryClient.invalidateQueries({ queryKey: ['storage'] });
      
      // Remove the query parameters from the URL without reloading the page
      window.history.replaceState({}, document.title, window.location.pathname);
      
      // Navigate back to dashboard after successful payment
      setTimeout(() => {
        navigate('/dashboard');
      }, 1000);
    } catch (error) {
      toast.error('Payment verification failed. Please try again or contact support.');
      console.error('Payment verification error:', error);
    } finally {
      setIsProcessingPayment(false);
    }
  };
  
  // Fetch current subscription and storage usage
  const { data: currentSubscription } = useQuery({
    queryKey: ['subscription'],
    queryFn: subscriptionService.getCurrentSubscription,
  });

  const { data: storageUsage } = useQuery({
    queryKey: ['storage'],
    queryFn: subscriptionService.getStorageUsage,
  });

  // Mutation for handling plan payment/update
  const handlePlanPayment = useMutation({
    mutationFn: (plan: any) => subscriptionService.handlePlanPayment(plan),
    onSuccess: () => {
      // For free plans, this will be called immediately
      // For paid plans, this will redirect to eSewa before completing
      if (!isProcessingPayment) {
        toast.success('Subscription updated successfully');
        queryClient.invalidateQueries({ queryKey: ['subscription'] });
        queryClient.invalidateQueries({ queryKey: ['storage'] });
        
        // Emit subscription-updated event
        eventBus.emit('subscription-updated');
        
        // Navigate back to dashboard after successful update
        setTimeout(() => {
          navigate('/dashboard');
        }, 1000);
      }
    },
    onError: (error) => {
      toast.error('Failed to update subscription');
      console.error('Subscription update error:', error);
    },
  });

  // Handle subscription update
  const handleUpdateSubscription = (plan: any) => {
    if (currentSubscription?.id === plan.id) {
      toast.info('You are already subscribed to this plan');
      return;
    }
    
    handlePlanPayment.mutate(plan);
  };

  // Define our plans with focus on storage
  const plans = [
    {
      id: 1,
      name: "Free",
      price: 0,
      storage: 5 * 1024 * 1024, // 5MB
      features: [
        "5MB Document Storage",
        "Basic document upload",
        "Unlimited QR codes",
        "Standard security",
        "Community support"
      ],
      icon: <Database className="h-5 w-5" />
    },
    {
      id: 2,
      name: "Pro",
      price: isBusinessPlan ? 999 : 499,
      storage: 15 * 1024 * 1024, // 15MB
      features: [
        "15MB Document Storage",
        "Advanced document management",
        "Priority support",
        "Document versioning",
        "Custom expiration dates"
      ],
      icon: <Shield className="h-5 w-5" />
    },
    {
      id: 3,
      name: "Enterprise",
      price: isBusinessPlan ? 8000 : 4000,
      storage: 0, // Unlimited
      features: [
        "Unlimited Document Storage",
        "Team management",
        "API access",
        "Custom integrations",
        "Dedicated support"
      ],
      icon: <Users className="h-5 w-5" />
    }
  ];

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <main className="container mx-auto px-4 pt-24 pb-16">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="max-w-6xl mx-auto"
        >
          {/* Header Card */}
          <div className="bg-gradient-to-r from-primary/90 to-tertiary/90 rounded-2xl p-8 text-white mb-8 relative overflow-hidden">
            <div className="absolute top-0 right-0 w-64 h-64 bg-white/10 rounded-full -mt-32 -mr-32" />
            <div className="absolute bottom-0 left-0 w-32 h-32 bg-white/5 rounded-full -mb-16 -ml-16" />
            <div className="relative z-10">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                <div>
                  <Button 
                    variant="ghost" 
                    onClick={() => navigate(-1)}
                    className="mb-2 text-white/80 hover:text-white hover:bg-white/10 -ml-3"
                  >
                    <ArrowLeft className="mr-2 h-4 w-4" /> Back
                  </Button>
                  
                  <h1 className="text-3xl font-bold">Choose Your Storage Plan</h1>
                  <p className="text-white/80 mt-2 max-w-xl">
                    Select the storage capacity that fits your document management needs
                  </p>
                </div>
                
                {/* Current Plan & Usage Summary */}
                {currentSubscription && storageUsage && (
                  <Card className="bg-white/10 backdrop-blur-sm border-white/20 w-full md:w-auto">
                    <CardContent className="p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <Crown className="h-5 w-5 text-yellow-400" />
                        <span className="font-semibold text-white">Current: {currentSubscription.name} Plan</span>
                      </div>
                      <div className="space-y-2">
                        <div className="flex justify-between text-sm text-white/80">
                          <span>Storage Used</span>
                          <span>{formatStorage(storageUsage.used)} / {formatStorage(storageUsage.limit)}</span>
                        </div>
                        <Progress 
                          value={(storageUsage.used / storageUsage.limit) * 100} 
                          className="h-2 bg-white/20"
                        />
                      </div>
                    </CardContent>
                  </Card>
                )}
              </div>
            </div>
          </div>
          
          {/* Payment Processing Indicator */}
          {isProcessingPayment && (
            <div className="mb-8 p-4 rounded-lg bg-yellow-50 border border-yellow-100 text-yellow-800 flex items-center justify-center">
              <div className="w-6 h-6 rounded-full border-2 border-yellow-400 border-t-transparent animate-spin mr-3"></div>
              <span>Processing your payment, please wait...</span>
            </div>
          )}
          
          {/* Personal/Business Toggle */}
          <div className="flex items-center justify-center mb-12">
            <span className={isBusinessPlan ? "text-muted-foreground" : "font-medium"}>Personal</span>
            <Switch 
              checked={isBusinessPlan} 
              onCheckedChange={setIsBusinessPlan}
              className="mx-4"
            />
            <span className={!isBusinessPlan ? "text-muted-foreground" : "font-medium"}>Business</span>
          </div>
          
          {/* Plan Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            {plans.map((plan, index) => (
              <motion.div
                key={plan.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
              >
                <Card 
                  className={`h-full overflow-hidden transition-all hover:shadow-md ${
                    currentSubscription?.id === plan.id 
                      ? 'border-primary border-2' 
                      : 'border-border hover:border-primary/50'
                  }`}
                >
                  {currentSubscription?.id === plan.id && (
                    <div className="bg-primary py-1 px-3 text-primary-foreground text-xs font-medium text-center">
                      Your Current Plan
                    </div>
                  )}
                  
                  <CardContent className="p-6">
                    <div className="flex justify-between items-center mb-4">
                      <div className="flex items-center gap-2">
                        <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                          {plan.icon}
                        </div>
                        <h3 className="text-xl font-semibold">{plan.name}</h3>
                      </div>
                      
                      <div className="flex flex-col">
                        <span className="text-3xl font-bold">
                          {plan.price === 0 ? (
                            "Free"
                          ) : (
                            <>
                              NPR {plan.price.toLocaleString()}
                              <span className="text-sm font-normal text-muted-foreground">/month</span>
                            </>
                          )}
                        </span>
                      </div>
                    </div>
                    
                    {/* Storage Highlight */}
                    <div className="bg-muted/50 rounded-lg p-4 mb-6">
                      <div className="font-medium mb-2">Storage Capacity</div>
                      <div className="text-2xl font-bold text-primary">{formatStorage(plan.storage)}</div>
                    </div>
                    
                    {/* Features */}
                    <div className="mb-8">
                      <div className="font-medium mb-3">Features</div>
                      <ul className="space-y-2">
                        {plan.features.map((feature, i) => (
                          <li key={i} className="flex items-start">
                            <Check className="h-4 w-4 text-primary mr-2 mt-1 flex-shrink-0" />
                            <span className="text-sm">{feature}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                    
                    <Button 
                      className="w-full" 
                      variant={currentSubscription?.id === plan.id ? "outline" : "default"}
                      disabled={handlePlanPayment.isPending || isProcessingPayment || currentSubscription?.id === plan.id}
                      onClick={() => handleUpdateSubscription(plan)}
                    >
                      {currentSubscription?.id === plan.id 
                        ? 'Current Plan' 
                        : handlePlanPayment.isPending || isProcessingPayment
                          ? 'Processing...' 
                          : `${plan.price === 0 ? 'Select' : 'Upgrade to'} ${plan.name}`}
                    </Button>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
          
          {/* Additional Info */}
          <div className="mt-12">
            <h2 className="text-xl font-semibold mb-4">Subscription Information</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <Card>
                <CardContent className="p-6">
                  <div className="flex flex-col items-center text-center">
                    <Clock className="h-10 w-10 text-muted-foreground mb-3" />
                    <h3 className="text-lg font-medium mb-2">Billing Cycle</h3>
                    <p className="text-sm text-muted-foreground">All plans are billed monthly. You can change or cancel your plan at any time.</p>
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-6">
                  <div className="flex flex-col items-center text-center">
                    <Shield className="h-10 w-10 text-muted-foreground mb-3" />
                    <h3 className="text-lg font-medium mb-2">Secure Payments</h3>
                    <p className="text-sm text-muted-foreground">All payments are processed securely through eSewa payment gateway.</p>
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-6">
                  <div className="flex flex-col items-center text-center">
                    <Users className="h-10 w-10 text-muted-foreground mb-3" />
                    <h3 className="text-lg font-medium mb-2">Need Help?</h3>
                    <p className="text-sm text-muted-foreground">Contact our support team if you have any questions about billing or plans.</p>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </motion.div>
      </main>
    </div>
  );
};

export default Subscription; 