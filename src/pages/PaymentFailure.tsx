import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import Navbar from '@/components/layout/Navbar';
import { motion } from 'framer-motion';

const PaymentFailure = () => {
  const navigate = useNavigate();

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
          <Card className="overflow-hidden border-2 border-red-500">
            <div className="bg-red-500 py-3 px-4 text-white text-center">
              <h2 className="text-xl font-bold">Payment Failed</h2>
            </div>
            <CardContent className="p-6">
              <div className="flex flex-col items-center text-center mb-6">
                <AlertTriangle className="h-16 w-16 text-red-500 mb-4" />
                <h3 className="text-xl font-semibold mb-2">Payment Unsuccessful</h3>
                <p className="text-muted-foreground">
                  We couldn't process your payment. No funds have been deducted from your account.
                </p>
              </div>
              
              <div className="space-y-4">
                <Button 
                  variant="default"
                  className="w-full"
                  onClick={() => navigate('/subscription')}
                >
                  Try Again
                </Button>
                
                <Button 
                  variant="outline"
                  className="w-full"
                  onClick={() => navigate('/dashboard')}
                >
                  <ArrowLeft className="mr-2 h-4 w-4" />
                  Back to Dashboard
                </Button>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </main>
    </div>
  );
};

export default PaymentFailure; 