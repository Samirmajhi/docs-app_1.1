import React, { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { ArrowLeft, CheckCircle, AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import Navbar from '@/components/layout/Navbar';
import { motion } from 'framer-motion';
import { toast } from 'sonner';
import subscriptionService from '@/services/subscription.service';
import { useQueryClient } from '@tanstack/react-query';
import eventBus from '@/utils/eventBus';

const PaymentSuccess = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();
  const [verificationStatus, setVerificationStatus] = useState<'processing' | 'success' | 'error'>('processing');
  const [errorMessage, setErrorMessage] = useState<string>('');

  useEffect(() => {
    const handlePaymentVerification = async () => {
      try {
        setVerificationStatus('processing');
        const searchParams = new URLSearchParams(location.search);
        const data = searchParams.get('data');
        
        if (!data) {
          console.error('No payment data found in URL');
          setVerificationStatus('error');
          setErrorMessage('No payment data found');
          return;
        }
        
        // Attempt to verify the payment
        const response = await subscriptionService.verifyPayment(data);
        
        if (response && response.success) {
          setVerificationStatus('success');
          toast.success('Payment successful! Your subscription has been updated.');
          
          // Aggressively force refresh all subscription and storage data
          await Promise.all([
            queryClient.invalidateQueries({ queryKey: ['subscription'] }),
            queryClient.invalidateQueries({ queryKey: ['storage'] })
          ]);
          
          // Force immediate refetch
          await Promise.all([
            queryClient.refetchQueries({ queryKey: ['subscription'] }),
            queryClient.refetchQueries({ queryKey: ['storage'] })
          ]);
          
          // Wait a moment and force another refetch to ensure data is updated
          setTimeout(async () => {
            await Promise.all([
              queryClient.refetchQueries({ queryKey: ['subscription'], exact: true }),
              queryClient.refetchQueries({ queryKey: ['storage'], exact: true })
            ]);
            
            // Notify other components about the subscription update
            eventBus.emit('subscription-updated', {
              timestamp: Date.now(),
              plan: response?.paymentData?.planId
            });
          }, 2000);
        } else {
          setVerificationStatus('error');
          setErrorMessage(response?.message || 'Payment verification failed');
          toast.error('Error verifying payment. Please contact support.');
        }
        
        // Remove the query parameters from the URL without reloading the page
        window.history.replaceState({}, document.title, window.location.pathname);
      } catch (error: any) {
        console.error('Payment verification error:', error);
        setVerificationStatus('error');
        setErrorMessage(error?.message || 'Error verifying payment');
        toast.error('Error verifying payment. Please contact support.');
      }
    };

    handlePaymentVerification();
  }, [location, queryClient]);

  // Function to refresh data and go to dashboard
  const goToDashboard = async () => {
    // Force refresh one more time before navigating
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['subscription'] }),
      queryClient.invalidateQueries({ queryKey: ['storage'] }),
      queryClient.refetchQueries({ queryKey: ['subscription'] }),
      queryClient.refetchQueries({ queryKey: ['storage'] })
    ]);
    
    // Emit event to notify components
    eventBus.emit('subscription-updated', { timestamp: Date.now() });
    
    // Navigate to dashboard
    navigate('/dashboard');
  };

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <main className="container mx-auto px-4 pt-24 pb-16">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="max-w-md mx-auto"
        >
          <Card className={`overflow-hidden border-2 ${verificationStatus === 'error' ? 'border-red-500' : 'border-green-500'}`}>
            <div className={`${verificationStatus === 'error' ? 'bg-red-500' : 'bg-green-500'} py-3 px-4 text-white text-center`}>
              <h2 className="text-xl font-bold">
                {verificationStatus === 'processing' && 'Processing Payment...'}
                {verificationStatus === 'success' && 'Payment Successful'}
                {verificationStatus === 'error' && 'Payment Verification Error'}
              </h2>
            </div>
            <CardContent className="p-6">
              <div className="flex flex-col items-center text-center mb-6">
                {verificationStatus === 'processing' && (
                  <div className="animate-spin h-16 w-16 border-4 border-green-500 border-t-transparent rounded-full mb-4"></div>
                )}
                {verificationStatus === 'success' && (
                  <CheckCircle className="h-16 w-16 text-green-500 mb-4" />
                )}
                {verificationStatus === 'error' && (
                  <AlertCircle className="h-16 w-16 text-red-500 mb-4" />
                )}
                
                <h3 className="text-xl font-semibold mb-2">
                  {verificationStatus === 'processing' && 'Processing...'}
                  {verificationStatus === 'success' && 'Thank You!'}
                  {verificationStatus === 'error' && 'Verification Failed'}
                </h3>
                
                <p className="text-muted-foreground">
                  {verificationStatus === 'processing' && 'Please wait while we verify your payment...'}
                  {verificationStatus === 'success' && 'Your payment has been processed successfully and your subscription has been updated.'}
                  {verificationStatus === 'error' && (
                    <>
                      {errorMessage || 'There was an error verifying your payment. Please contact support.'}
                      <br />
                      <span className="text-sm mt-1">Your account may still have been updated, please check your subscription status.</span>
                    </>
                  )}
                </p>
              </div>
              
              <div className="space-y-4">
                <Button 
                  variant="default"
                  className="w-full"
                  onClick={goToDashboard}
                >
                  Go to Dashboard
                </Button>
                
                <Button 
                  variant="outline"
                  className="w-full"
                  onClick={() => navigate('/subscription')}
                >
                  <ArrowLeft className="mr-2 h-4 w-4" />
                  Back to Plans
                </Button>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </main>
    </div>
  );
};

export default PaymentSuccess; 