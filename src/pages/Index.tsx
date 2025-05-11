
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Shield, FileText, QrCode, ArrowRight } from 'lucide-react';
import AuthForm from '@/components/auth/AuthForm';
import AuthWrapper from '@/components/layout/AuthWrapper';
import { motion } from 'framer-motion';

const Index = () => {
  const navigate = useNavigate();

  const features = [
    {
      icon: <Shield className="h-6 w-6 text-primary" />,
      title: "Secure Storage",
      description: "Your documents are encrypted and stored securely"
    },
    {
      icon: <FileText className="h-6 w-6 text-primary" />,
      title: "Easy Management",
      description: "Upload, view and manage all your documents in one place"
    },
    {
      icon: <QrCode className="h-6 w-6 text-primary" />,
      title: "QR Sharing",
      description: "Share documents securely via QR code with controlled access"
    }
  ];

  return (
    <AuthWrapper 
      title="Welcome to SecureDoc" 
      subtitle="Login to your account or create a new one to get started."
    >
      <div className="flex flex-col gap-8">
        <AuthForm />
        
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="mt-8 pt-8 border-t border-gray-200"
        >
          <h3 className="text-lg font-medium text-center mb-6">Why Choose SecureDoc?</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {features.map((feature, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: 0.3 + index * 0.1 }}
                className="bg-secondary/50 p-4 rounded-lg text-center"
              >
                <div className="bg-primary/10 w-12 h-12 rounded-full flex items-center justify-center mx-auto mb-3">
                  {feature.icon}
                </div>
                <h4 className="font-medium mb-1">{feature.title}</h4>
                <p className="text-sm text-muted-foreground">{feature.description}</p>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </AuthWrapper>
  );
};

export default Index;
