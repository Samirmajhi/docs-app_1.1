
import React, { useEffect } from 'react';
import Navbar from '@/components/layout/Navbar';
import QRCodeGenerator from '@/components/sharing/QRCodeGenerator';
import { motion } from 'framer-motion';
import { FileText, Shield, QrCode } from 'lucide-react';
import { useAuth } from '@/context/AuthContext';

const Share = () => {
  const { user } = useAuth();
  
  // Log user details for debugging owner verification issues
  useEffect(() => {
    if (user) {
      console.log('Current user from context:', {
        id: user.id,
        fullName: user.fullName,
        mobileNumber: user.mobileNumber,
        pin: user.pin ? '✓ Present' : '✗ Missing'
      });
    }
  }, [user]);
  
  // Check if PIN is set
  const isPinSet = user && user.pin && user.pin.trim() !== '';
  
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <main className="container mx-auto px-4 pt-24 pb-16">
        <div className="max-w-5xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <h1 className="text-3xl font-bold text-center mb-4">Share Your Documents</h1>
            <p className="text-muted-foreground text-center mb-12 max-w-lg mx-auto">
              Generate a QR code that provides secure access to your document vault
            </p>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-12 items-center">
              <div className="flex justify-center">
                <QRCodeGenerator />
              </div>
              
              <div className="space-y-6">
                <h2 className="text-2xl font-semibold mb-4">How It Works</h2>
                
                <div className="space-y-6">
                  <div className="flex gap-4">
                    <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                      <QrCode className="w-6 h-6 text-primary" />
                    </div>
                    <div>
                      <h3 className="font-medium mb-1">Share Your QR Code</h3>
                      <p className="text-muted-foreground text-sm">
                        Anyone with this QR code can request access to your documents.
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex gap-4">
                    <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                      <FileText className="w-6 h-6 text-primary" />
                    </div>
                    <div>
                      <h3 className="font-medium mb-1">Document Selection</h3>
                      <p className="text-muted-foreground text-sm">
                        Users can select which documents they need access to. You retain full control.
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex gap-4">
                    <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                      <Shield className="w-6 h-6 text-primary" />
                    </div>
                    <div>
                      <h3 className="font-medium mb-1">Secure Verification</h3>
                      <p className="text-muted-foreground text-sm">
                        Approve or deny access requests. Only you can authorize document access.
                      </p>
                    </div>
                  </div>
                </div>
                
                <div className="bg-muted p-4 rounded-lg mt-6">
                  <h3 className="font-medium mb-2">Security Note</h3>
                  <p className="text-sm text-muted-foreground">
                    Your documents remain encrypted and secure. The QR code stays active for 30 days. You can regenerate it at any time.
                  </p>
                  
                  {user && (
                    <div className="mt-4 p-3 bg-primary/10 rounded-lg">
                      <h4 className="text-sm font-medium text-primary mb-1">Your Authentication Details</h4>
                      <ul className="text-xs text-muted-foreground space-y-1">
                        <li><span className="font-medium">Mobile:</span> {user.mobileNumber || 'Not set'}</li>
                        <li><span className="font-medium">PIN:</span> {isPinSet ? '••••' : 'Not set (required for verification)'}</li>
                      </ul>
                      <p className="text-xs mt-1">You'll need these to authenticate as the document owner.</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </main>
    </div>
  );
};

export default Share;