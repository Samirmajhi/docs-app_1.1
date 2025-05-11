import React, { useState, useRef } from 'react';
import { Upload, X, File, Check, Crown } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { toast } from 'sonner';
import { motion, AnimatePresence } from 'framer-motion';
import documentService from '@/services/document.service';
import { useNavigate } from 'react-router-dom';

interface DocumentUploadProps {
  onSuccess: (file: File) => void;
}

const DocumentUpload = ({ onSuccess }: DocumentUploadProps) => {
  const navigate = useNavigate();
  const [isDragging, setIsDragging] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [fileName, setFileName] = useState('');
  const [progress, setProgress] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [uploaded, setUploaded] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isProcessed, setIsProcessed] = useState(false);
  const [storageError, setStorageError] = useState<{
    used: number;
    limit: number;
    would_be_used: number;
    plan_name: string;
  } | null>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const droppedFile = e.dataTransfer.files[0];
      setFile(droppedFile);
      // Set default name to original file name, but allow user to change it
      setFileName(droppedFile.name);
      setIsProcessed(false); // Reset processed state when new file is dropped
      setStorageError(null); // Clear any previous storage error
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const selectedFile = e.target.files[0];
      setFile(selectedFile);
      // Set default name to original file name, but allow user to change it
      setFileName(selectedFile.name);
      setIsProcessed(false); // Reset processed state when new file is selected
      setStorageError(null); // Clear any previous storage error
    }
  };

  const formatStorage = (bytes: number): string => {
    const mb = bytes / (1024 * 1024);
    return `${mb.toFixed(1)} MB`;
  };

  const handleUpgrade = () => {
    navigate('/subscription');
  };

  const handleUpload = async () => {
    if (!file || !fileName.trim()) {
      toast.error('Please select a file and provide a name');
      return;
    }
    
    if (isProcessed) {
      console.log('Preventing duplicate upload - already processed');
      return;
    }
    
    setIsProcessed(true);
    setUploading(true);
    setProgress(0);
    setStorageError(null);
    
    try {
      // First check if the file would exceed storage limits
      let canProceed = true;
      
      try {
        console.log('Checking storage limits for file size:', file.size);
        const storageCheck = await documentService.checkStorageLimit(file.size);
        
        if (!storageCheck.has_available_storage) {
          console.log('Storage limit would be exceeded:', storageCheck.storage_info);
          setStorageError(storageCheck.storage_info);
          canProceed = false;
        } else {
          console.log('Storage check passed, proceeding with upload');
        }
      } catch (storageError) {
        console.error('Failed to check storage limits:', storageError);
        // Allow upload to proceed - server will still enforce limits
        console.log('Continuing with upload despite storage check error');
      }
      
      if (!canProceed) {
        setUploading(false);
        return;
      }
      
      // Simulate progress updates
      const progressInterval = setInterval(() => {
        setProgress((prev) => {
          const newProgress = prev + Math.random() * 15;
          return newProgress >= 90 ? 90 : newProgress;
        });
      }, 200);
      
      // Upload the file with custom name if provided
      console.log('Starting file upload with name:', fileName);
      const result = await documentService.uploadDocument(file, fileName);
      
      // Clear the interval and set progress to 100%
      clearInterval(progressInterval);
      setProgress(100);
      
      // Set uploaded state
      setUploaded(true);
      setUploading(false);
      console.log('Upload completed successfully');
      
      // Reset after 2 seconds
      setTimeout(() => {
        setFile(null);
        setFileName('');
        setUploaded(false);
        setProgress(0);
        setIsProcessed(false);
        if (onSuccess) onSuccess(file);
      }, 2000);
      
    } catch (error: any) {
      console.error('Error uploading document:', error);
      
      // Clear any progress interval that might be running
      setProgress(0);
      
      // Check for storage limit exceeded error
      if (error.response?.status === 413 && error.response?.data?.error === 'subscription_limit_exceeded') {
        setStorageError(error.response.data.details);
        toast.error('Storage limit exceeded. Please upgrade your subscription to continue uploading.');
      } else if (error.response?.status === 401 || error.response?.status === 403) {
        // Authentication error
        toast.error('Authentication error. Please log in again.');
        // Optionally redirect to login page
      } else if (error.response?.status === 404 && error.response?.data?.error === 'user_not_found') {
        // User not found error
        toast.error('Your account information could not be found. Please log in again.');
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        window.location.href = '/login';
      } else {
        // Show more specific error message if available
        const errorMessage = error.response?.data?.message || 'Failed to upload document. Please try again.';
        toast.error(errorMessage);
      }
      
      setUploading(false);
      setIsProcessed(false);
    }
  };

  const resetUpload = () => {
    setFile(null);
    setFileName('');
    setProgress(0);
    setUploaded(false);
    setUploading(false);
    setIsProcessed(false);
    setStorageError(null);
  };

  return (
    <div className="w-full">
      <AnimatePresence mode="wait">
        {!file ? (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.3 }}
            className={`border-2 border-dashed rounded-xl p-8 text-center ${
              isDragging ? 'border-primary bg-primary/5' : 'border-muted'
            }`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
          >
            <div className="flex flex-col items-center justify-center gap-3">
              <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center mb-2">
                <Upload className="w-8 h-8 text-primary" />
              </div>
              <h3 className="text-lg font-medium">Drag and drop your file</h3>
              <p className="text-muted-foreground mb-4">or click to browse files</p>
              
              <Button
                variant="outline"
                className="mt-2"
                onClick={() => fileInputRef.current?.click()}
              >
                Select File
              </Button>
              
              <input
                type="file"
                ref={fileInputRef}
                className="hidden"
                onChange={handleFileChange}
              />
              
              <p className="text-xs text-muted-foreground mt-4">
                Supported file formats: PDF, DOCX, XLSX, JPG, PNG, and more
              </p>
            </div>
          </motion.div>
        ) : (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.3 }}
            className="border rounded-xl p-6"
          >
            <div className="flex items-start gap-4">
              <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
                <File className="w-6 h-6 text-primary" />
              </div>
              
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-medium truncate max-w-xs">
                    {file.name}
                  </h3>
                  {!uploading && !uploaded && (
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={resetUpload}
                      className="text-muted-foreground"
                    >
                      <X className="w-5 h-5" />
                    </Button>
                  )}
                </div>
                
                <p className="text-sm text-muted-foreground mb-4">
                  {(file.size / 1024 / 1024).toFixed(2)} MB • {file.type || 'Unknown type'}
                </p>
                
                {!uploading && !uploaded && !storageError && (
                  <div className="space-y-3">
                    <div className="space-y-1">
                      <Label htmlFor="filename">Document Name</Label>
                      <Input
                        id="filename"
                        value={fileName}
                        onChange={(e) => setFileName(e.target.value)}
                        placeholder="Enter a name for this document"
                      />
                    </div>
                    
                    <div className="flex gap-2 mt-4">
                      <Button 
                        className="w-full"
                        onClick={handleUpload}
                      >
                        Upload Document
                      </Button>
                    </div>
                  </div>
                )}
                
                {/* Storage Limit Exceeded Error */}
                {storageError && (
                  <div className="mt-4 p-4 bg-amber-50 border border-amber-200 rounded-lg space-y-3">
                    <div className="flex items-center gap-2 text-amber-700">
                      <Crown className="w-5 h-5" />
                      <span className="font-medium">Storage Limit Exceeded</span>
                    </div>
                    
                    <p className="text-sm text-amber-700">
                      Your {storageError.plan_name} plan has a limit of {formatStorage(storageError.limit)}.
                      This upload would exceed your available storage.
                    </p>
                    
                    <div className="space-y-1">
                      <div className="flex justify-between text-xs text-amber-700">
                        <span>Current usage: {formatStorage(storageError.used)}</span>
                        <span>Required: {formatStorage(storageError.would_be_used)}</span>
                      </div>
                      <Progress 
                        value={(storageError.used / storageError.limit) * 100} 
                        className="h-2 bg-amber-200"
                        indicatorClassName="bg-amber-500"
                      />
                    </div>
                    
                    <div className="flex gap-2">
                      <Button 
                        className="w-full"
                        onClick={handleUpgrade}
                        variant="default"
                      >
                        Upgrade Plan
                      </Button>
                      <Button 
                        className="w-full"
                        onClick={resetUpload}
                        variant="outline"
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                )}
                
                {uploading && (
                  <div className="space-y-2 mt-2">
                    <div className="flex justify-between text-sm">
                      <span>Uploading...</span>
                      <span>{Math.round(progress)}%</span>
                    </div>
                    <Progress value={progress} className="h-2" />
                  </div>
                )}
                
                {uploaded && (
                  <div className="flex items-center gap-2 text-green-600 mt-2">
                    <Check className="w-5 h-5" />
                    <span>Upload complete</span>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default DocumentUpload;