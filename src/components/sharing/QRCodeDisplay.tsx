
import React from 'react';
import { motion } from 'framer-motion';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Download, Copy, Share2 } from 'lucide-react';
import { toast } from 'sonner';

interface QRCodeDisplayProps {
  qrCode: string;
  expiresAt: string;
  accessCode?: string;
  onDownload?: () => void;
}

const QRCodeDisplay: React.FC<QRCodeDisplayProps> = ({ 
  qrCode, 
  expiresAt, 
  accessCode,
  onDownload
}) => {
  const formattedExpiry = new Date(expiresAt).toLocaleDateString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });

  const handleDownload = () => {
    if (onDownload) {
      onDownload();
      return;
    }
    
    // Default download behavior
    const link = document.createElement('a');
    link.href = qrCode;
    link.download = 'securedoc-qrcode.png';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast.success('QR Code downloaded successfully');
  };

  const handleCopyLink = () => {
    // In a real app, this would be a URL to access the documents
    navigator.clipboard.writeText(`https://securedoc.com/access?code=${btoa(Date.now().toString())}`);
    toast.success('Access link copied to clipboard');
  };

  const handleShare = async () => {
    try {
      if (navigator.share) {
        await navigator.share({
          title: 'SecureDoc Shared Documents',
          text: 'I\'ve shared some documents with you securely via SecureDoc.',
          url: `https://securedoc.com/access?code=${btoa(Date.now().toString())}`,
        });
        toast.success('Shared successfully');
      } else {
        handleCopyLink();
      }
    } catch (error) {
      console.error('Error sharing:', error);
      handleCopyLink();
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <Card className="overflow-hidden border-2 border-primary/20">
        <CardHeader className="bg-primary/5 border-b border-primary/10">
          <CardTitle className="text-center text-xl">Your Secure QR Code</CardTitle>
          <CardDescription className="text-center">
            Scan this code to access shared documents
          </CardDescription>
        </CardHeader>
        
        <CardContent className="p-6 flex flex-col items-center">
          <div className="bg-white p-4 rounded-lg shadow-sm border mb-4">
            <img 
              src={qrCode} 
              alt="QR Code" 
              className="w-56 h-56 object-contain" 
            />
          </div>
          
          {accessCode && (
            <div className="mb-4 text-center">
              <p className="text-sm text-muted-foreground mb-1">Access Code</p>
              <div className="bg-secondary/50 rounded-md px-4 py-2 font-mono text-lg tracking-widest">
                {accessCode}
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                Share this code with the recipient
              </p>
            </div>
          )}
          
          <div className="text-sm text-muted-foreground text-center mt-2">
            <p>This QR code will expire on:</p>
            <p className="font-medium text-foreground">{formattedExpiry}</p>
          </div>
        </CardContent>
        
        <CardFooter className="flex flex-col sm:flex-row gap-2 bg-muted/30 border-t p-4">
          <Button 
            variant="outline" 
            className="w-full sm:w-auto flex gap-2 items-center" 
            onClick={handleDownload}
          >
            <Download className="h-4 w-4" />
            Download
          </Button>
          <Button 
            variant="outline" 
            className="w-full sm:w-auto flex gap-2 items-center" 
            onClick={handleCopyLink}
          >
            <Copy className="h-4 w-4" />
            Copy Link
          </Button>
          <Button 
            variant="outline" 
            className="w-full sm:w-auto flex gap-2 items-center" 
            onClick={handleShare}
          >
            <Share2 className="h-4 w-4" />
            Share
          </Button>
        </CardFooter>
      </Card>
    </motion.div>
  );
};

export default QRCodeDisplay;
