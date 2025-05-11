import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { 
  Shield, 
  FileCheck, 
  Phone, 
  Lock, 
  Check, 
  ArrowLeft,
  Eye,
  EyeOff,
  AlertCircle,
  MoreVertical,
  File,
  FileText,
  Loader2,
  XCircle,
  Download
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { toast } from 'sonner';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '@/components/ui/select';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
  DropdownMenuLabel,
  DropdownMenuSub,
  DropdownMenuSubTrigger,
  DropdownMenuSubContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem
} from '@/components/ui/dropdown-menu';
import qrcodeService from '@/services/qrcode.service';
import documentService from '@/services/document.service';
import DocumentViewer from '@/components/documents/DocumentViewer';
import accessService from '@/services/access.service';

type AuthMode = 'initial' | 'scanner' | 'owner-verify' | 'access-granted';

// Phone number validation regex - Using international format
const PHONE_REGEX = /^\d{10}$/;

const Access = () => {
  const [searchParams] = useSearchParams();
  const qrCode = searchParams.get('code');
  const [mode, setMode] = useState<AuthMode>('initial');
  const [scannerName, setScannerName] = useState('');
  const [scannerMobile, setScannerMobile] = useState('');
  const [selectedDocs, setSelectedDocs] = useState<string[]>([]);
  const [mobileNumber, setMobileNumber] = useState('');
  const [pin, setPin] = useState('');
  const [showPin, setShowPin] = useState(false);
  const [loading, setLoading] = useState(false);
  const [validating, setValidating] = useState(false);
  const [qrData, setQrData] = useState<any>(null);
  const [documents, setDocuments] = useState<any[]>([]);
  const [viewDocument, setViewDocument] = useState<any>(null);
  const [isViewDialogOpen, setIsViewDialogOpen] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);
  const [downloadFormat, setDownloadFormat] = useState("original");
  const [phoneError, setPhoneError] = useState('');
  const [qrValidated, setQrValidated] = useState(false);
  const [requestStatus, setRequestStatus] = useState<'pending' | 'approved' | 'denied' | 'modified' | null>(null);
  const [currentRequestId, setCurrentRequestId] = useState<string | null>(null);
  const [approvedDocuments, setApprovedDocuments] = useState<any[]>([]);
  const [isLoadingDocuments, setIsLoadingDocuments] = useState(false);
  const [permissionLevel, setPermissionLevel] = useState<string>('view_and_download');
  const navigate = useNavigate();
  
  console.log('QR code from URL:', qrCode);
  
  useEffect(() => {
    if (qrCode) {
      validateQrCode();
    }
  }, [qrCode]);

  useEffect(() => {
    if (requestStatus === 'approved' && currentRequestId) {
      loadApprovedDocuments();
    }
  }, [requestStatus, currentRequestId]);

  const validateQrCode = async () => {
    if (!qrCode) return;
    
    try {
      setLoading(true);
      setValidating(true);
      console.log('Validating QR code:', qrCode);
      
      const response = await qrcodeService.validateQRCode(qrCode);
      console.log('QR validation response:', response);
      
      setQrData(response.qrCode);
      setDocuments(response.qrCode.documents);
      setQrValidated(true);
      
      // No access code needed, just show the initial options screen
      setMode('initial');
    } catch (error) {
      console.error('QR validation error:', error);
      toast.error('Invalid or expired QR code');
      
      // Keep showing the initial UI with error message
      setMode('initial');
      setQrValidated(false);
    } finally {
      setLoading(false);
      setValidating(false);
    }
  };

  const validatePhoneNumber = (phone: string) => {
    if (!phone.trim()) {
      setPhoneError('Mobile number is required');
      return false;
    }
    
    if (!PHONE_REGEX.test(phone)) {
      setPhoneError('Mobile number must be exactly 10 digits');
      return false;
    }
    
    setPhoneError('');
    return true;
  };

  const handleScannerSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scannerName.trim()) {
      toast.error('Please enter your name');
      return;
    }
    
    if (!validatePhoneNumber(scannerMobile)) {
      return;
    }
    
    if (selectedDocs.length === 0) {
      toast.error('Please select at least one document');
      return;
    }
    
    try {
      setLoading(true);
      const response = await qrcodeService.requestAccess({
        qrCodeId: qrData.id,
        requesterName: scannerName,
        requesterMobile: scannerMobile,
        requestedDocuments: selectedDocs
      });
      
      setCurrentRequestId(response.accessRequestId);
      setRequestStatus('pending');
      setMode('access-granted');
      toast.success('Access request sent successfully');
      
      // Start polling for status updates
      let pollInterval: NodeJS.Timeout;
      
      const checkStatus = async () => {
        try {
          const statusResponse = await accessService.getRequestStatus(response.accessRequestId);
          console.log('Current status:', statusResponse.status);
          
          setRequestStatus(statusResponse.status);
          
          if (statusResponse.status === 'approved') {
            clearInterval(pollInterval);
            const docResponse = await accessService.getDocumentAccess(response.accessRequestId);
            setApprovedDocuments(docResponse.documents);
            
            // Get and set permission level if available
            if (docResponse.permissionLevel) {
              setPermissionLevel(docResponse.permissionLevel);
            }
            
            toast.success('Your request has been approved!');
          } else if (statusResponse.status === 'denied') {
            clearInterval(pollInterval);
            toast.error('Your request has been denied');
            setTimeout(() => {
              setMode('initial');
            }, 3000);
          }
        } catch (error) {
          console.error('Error checking status:', error);
          // Don't stop polling on error, just log it
        }
      };

      // Check immediately and then start polling
      await checkStatus();
      pollInterval = setInterval(checkStatus, 5000); // Poll every 5 seconds

      // Cleanup function
      return () => {
        if (pollInterval) {
          clearInterval(pollInterval);
        }
      };
    } catch (error: any) {
      console.error('Access request error:', error);
      toast.error(error.response?.data?.message || 'Failed to send access request');
    } finally {
      setLoading(false);
    }
  };

  const handleOwnerVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mobileNumber.trim() || !pin.trim()) {
      toast.error('Please enter both mobile number and PIN');
      return;
    }
    
    if (!validatePhoneNumber(mobileNumber)) {
      return;
    }
    
    try {
      setLoading(true);
      console.log('Verifying owner with:', mobileNumber, pin);
      const response = await qrcodeService.verifyOwner(mobileNumber, pin);
      
      console.log('Owner verification response:', response);
      toast.success('Owner verified successfully');
      
      // Set the documents and approved documents with the same data
      setDocuments(response.documents);
      setApprovedDocuments(response.documents);
      setRequestStatus('approved');
      // Owners always have full access to their documents
      setPermissionLevel('view_and_download');
      setMode('access-granted');
      
      // Store owner token if needed
      if (response.token) {
        localStorage.setItem('ownerToken', response.token);
      }
    } catch (error: any) {
      console.error('Owner verification error:', error);
      toast.error(error.response?.data?.message || 'Invalid PIN or mobile number');
    } finally {
      setLoading(false);
    }
  };

  const handleDocumentSelect = (docId: string) => {
    setSelectedDocs(prev => 
      prev.includes(docId) 
        ? prev.filter(id => id !== docId) 
        : [...prev, docId]
    );
  };

  const handleView = async (doc: any) => {
    try {
      setViewDocument(doc);
      setIsViewDialogOpen(true);
    } catch (error) {
      console.error('Error viewing document:', error);
      toast.error('Failed to view document');
    }
  };

  const handleCloseViewer = () => {
    console.log("Closing document viewer");
    setIsViewDialogOpen(false);
    // Add a slight delay before clearing the document to prevent flickering
    setTimeout(() => {
      console.log("Clearing document data");
      setViewDocument(null);
    }, 300);
  };

  const handleDownload = async (documentId: string, format: string) => {
    try {
      // If user doesn't have download permission, don't allow download
      if (!hasDownloadPermission) {
        toast.error('You only have view-only permission for this document');
        return;
      }
      
      setIsDownloading(true);
      const blob = await accessService.downloadDocument(currentRequestId!, documentId, format);
      
      // Get the file extension from the document type
      const fileExt = format === 'original' 
        ? documentId.split('.').pop()?.toLowerCase() || 'file'
        : format;
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `document-${documentId}.${fileExt}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      toast.success('Document downloaded successfully');
    } catch (error: any) {
      console.error('Download error:', error);
      
      // Handle permission denied error specifically
      if (error.response?.status === 403 && error.response?.data?.permissionLevel === 'view_only') {
        toast.error('You only have view-only permission for this document');
      } else {
        toast.error('Failed to download document');
      }
    } finally {
      setIsDownloading(false);
    }
  };

  const loadApprovedDocuments = async () => {
    try {
      setIsLoadingDocuments(true);
      const response = await accessService.getDocumentAccess(currentRequestId!);
      setApprovedDocuments(response.documents);
    } catch (error) {
      console.error('Error loading approved documents:', error);
      toast.error('Failed to load approved documents');
    } finally {
      setIsLoadingDocuments(false);
    }
  };

  const getDownloadFileName = (originalName: string, format: string) => {
    if (format === 'original') {
      return originalName;
    }
    
    const baseName = originalName.includes('.')
      ? originalName.substring(0, originalName.lastIndexOf('.'))
      : originalName;
      
    return `${baseName}.${format}`;
  };

  const getFileIcon = (type: string) => {
    if (type.includes('pdf')) {
      return <div className="w-8 h-8 bg-red-100 text-red-500 rounded-full flex items-center justify-center">PDF</div>;
    } else if (type.includes('word') || type.includes('doc')) {
      return <div className="w-8 h-8 bg-blue-100 text-blue-500 rounded-full flex items-center justify-center">DOC</div>;
    } else if (type.includes('excel') || type.includes('sheet')) {
      return <div className="w-8 h-8 bg-green-100 text-green-500 rounded-full flex items-center justify-center">XLS</div>;
    } else if (type.includes('image') || type.includes('jpg') || type.includes('png')) {
      return <div className="w-8 h-8 bg-purple-100 text-purple-500 rounded-full flex items-center justify-center">IMG</div>;
    } else {
      return <div className="w-8 h-8 bg-gray-100 text-gray-500 rounded-full flex items-center justify-center">FILE</div>;
    }
  };

  // Add an access request permission check
  const hasDownloadPermission = permissionLevel !== 'view_only';

  return (
    <div className="min-h-screen bg-gradient-to-b from-background to-muted/30 flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-2xl bg-white rounded-2xl shadow-lg overflow-hidden"
      >
        <div className="px-8 py-6 bg-gradient-to-r from-primary/90 to-tertiary/90 text-white">
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6" />
            <h1 className="text-xl font-semibold">SecureDoc Access Portal</h1>
          </div>
        </div>

        <div className="p-8">
          <AnimatePresence mode="wait">
            {mode === 'initial' && (
              <motion.div
                key="initial"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.3 }}
              >
                <div className="text-center py-4">
                  <h2 className="text-2xl font-semibold mb-4">Document Access Portal</h2>
                  <p className="text-muted-foreground mb-8">
                    Welcome to the secure document access portal. Please select how you would like to proceed.
                  </p>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Button 
                      variant="outline" 
                      size="lg"
                      className="py-8 flex flex-col items-center h-auto"
                      onClick={() => setMode('scanner')}
                      disabled={!qrValidated && !validating}
                    >
                      <FileCheck className="w-8 h-8 mb-2 text-primary" />
                      <span className="text-base font-medium">Request Document Access</span>
                      <span className="text-xs text-muted-foreground mt-1">For document requesters</span>
                    </Button>
                    
                    <Button 
                      variant="outline" 
                      size="lg"
                      className="py-8 flex flex-col items-center h-auto"
                      onClick={() => setMode('owner-verify')}
                    >
                      <Shield className="w-8 h-8 mb-2 text-primary" />
                      <span className="text-base font-medium">Authenticate as Owner</span>
                      <span className="text-xs text-muted-foreground mt-1">For document owners</span>
                    </Button>
                  </div>
                  
                  {qrCode && validating && (
                    <div className="mt-8 text-center">
                      <div className="inline-block w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin"></div>
                      <p className="mt-2 text-muted-foreground">Validating QR code...</p>
                    </div>
                  )}
                  
                  {qrCode && !qrValidated && !validating && (
                    <div className="mt-8 p-4 bg-red-50 text-red-800 rounded-lg flex items-center gap-2">
                      <AlertCircle className="w-5 h-5" />
                      <span>Invalid or expired QR code</span>
                    </div>
                  )}
                </div>
              </motion.div>
            )}

            {mode === 'scanner' && (
              <motion.div
                key="scanner"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.3 }}
              >
                <Button 
                  variant="ghost" 
                  size="sm" 
                  className="mb-4"
                  onClick={() => setMode('initial')}
                >
                  <ArrowLeft className="w-4 h-4 mr-1" />
                  Back
                </Button>
                
                <h2 className="text-xl font-semibold mb-4">Request Document Access</h2>
                {qrData && (
                  <div className="mb-6 bg-muted p-3 rounded-lg">
                    <p className="text-sm text-muted-foreground">
                      Requesting access to documents owned by: <span className="font-medium">{qrData.ownerName}</span>
                    </p>
                  </div>
                )}
                <p className="text-muted-foreground mb-6">
                  Select the documents you need access to and provide your contact information for the document owner.
                </p>
                
                <form onSubmit={handleScannerSubmit} className="space-y-6">
                  <div className="space-y-2">
                    <Label htmlFor="name">Your Full Name</Label>
                    <Input
                      id="name"
                      value={scannerName}
                      onChange={(e) => setScannerName(e.target.value)}
                      placeholder="John Doe"
                      required
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="mobile">Your Mobile Number</Label>
                    <div className="relative">
                      <Phone className="absolute left-3 top-3 h-5 w-5 text-muted-foreground" />
                      <Input
                        id="mobile"
                        type="tel"
                        value={scannerMobile}
                        onChange={(e) => {
                          setScannerMobile(e.target.value);
                          validatePhoneNumber(e.target.value);
                        }}
                        onBlur={() => validatePhoneNumber(scannerMobile)}
                        placeholder="+1 (555) 123-4567"
                        className="pl-10"
                        required
                      />
                    </div>
                    {phoneError && (
                      <p className="text-xs text-red-500">{phoneError}</p>
                    )}
                  </div>
                  
                  <div className="space-y-3">
                    <Label>Available Documents</Label>
                    <div className="border rounded-lg divide-y max-h-60 overflow-y-auto">
                      {documents && documents.length > 0 ? (
                        <>
                          {/* All Documents Option */}
                          <div 
                            className="flex items-center p-3 hover:bg-muted/50 transition-colors bg-muted"
                          >
                            <Checkbox 
                              id="doc-all"
                              checked={selectedDocs.length === documents.length}
                              onCheckedChange={(checked) => {
                                if (checked) {
                                  setSelectedDocs(documents.map((doc: any) => doc.id.toString()));
                                } else {
                                  setSelectedDocs([]);
                                }
                              }}
                              className="mr-3"
                            />
                            <Label 
                              htmlFor="doc-all"
                              className="flex-1 cursor-pointer font-medium"
                            >
                              All Documents ({documents.length})
                            </Label>
                          </div>
                          
                          {/* Individual Document Options */}
                          {documents.map((doc: any) => (
                            <div 
                              key={doc.id} 
                              className="flex items-center p-3 hover:bg-muted/50 transition-colors"
                            >
                              <Checkbox 
                                id={`doc-${doc.id}`}
                                checked={selectedDocs.includes(doc.id.toString())}
                                onCheckedChange={() => handleDocumentSelect(doc.id.toString())}
                                className="mr-3"
                              />
                              <Label 
                                htmlFor={`doc-${doc.id}`}
                                className="flex-1 cursor-pointer flex items-center"
                              >
                                <div className="flex items-center gap-3">
                                  {getFileIcon(doc.type)}
                                  <div>
                                    <div className="font-medium truncate max-w-[200px]">{doc.name}</div>
                                    <div className="text-xs text-muted-foreground">
                                      {doc.type} • {(doc.size / 1024).toFixed(1)} KB
                                    </div>
                                  </div>
                                </div>
                              </Label>
                            </div>
                          ))}
                        </>
                      ) : (
                        <div className="p-4 text-center text-muted-foreground">
                          No documents available
                        </div>
                      )}
                    </div>
                  </div>
                  
                  <Button type="submit" className="w-full" disabled={loading}>
                    {loading ? (
                      <div className="flex items-center">
                        <svg className="animate-spin -ml-1 mr-3 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        Sending Request...
                      </div>
                    ) : (
                      'Send Access Request'
                    )}
                  </Button>
                </form>
              </motion.div>
            )}

            {mode === 'owner-verify' && (
              <motion.div
                key="owner-verify"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.3 }}
              >
                <Button 
                  variant="ghost" 
                  size="sm" 
                  className="mb-4"
                  onClick={() => setMode('initial')}
                >
                  <ArrowLeft className="w-4 h-4 mr-1" />
                  Back
                </Button>
                
                <h2 className="text-xl font-semibold mb-4">Authenticate as Owner</h2>
                <p className="text-muted-foreground mb-6">
                  Please verify your identity using your registered mobile number and PIN.
                </p>
                
                <form onSubmit={handleOwnerVerify} className="space-y-6">
                  <div className="space-y-2">
                    <Label htmlFor="mobile">Mobile Number</Label>
                    <div className="relative">
                      <Phone className="absolute left-3 top-3 h-5 w-5 text-muted-foreground" />
                      <Input
                        id="mobile"
                        type="tel"
                        value={mobileNumber}
                        onChange={(e) => {
                          setMobileNumber(e.target.value);
                          validatePhoneNumber(e.target.value);
                        }}
                        onBlur={() => validatePhoneNumber(mobileNumber)}
                        placeholder="+1 (555) 123-4567"
                        className="pl-10"
                        required
                      />
                    </div>
                    {phoneError && (
                      <p className="text-xs text-red-500">{phoneError}</p>
                    )}
                    <p className="text-xs text-muted-foreground mt-1">
                      Enter the same mobile number you used during registration
                    </p>
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="pin">Security PIN</Label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-3 h-5 w-5 text-muted-foreground" />
                      <Input
                        id="pin"
                        type={showPin ? "text" : "password"}
                        value={pin}
                        onChange={(e) => setPin(e.target.value)}
                        placeholder="Enter your PIN"
                        className="pl-10 pr-10"
                        required
                      />
                      <button
                        type="button"
                        className="absolute right-3 top-3 text-muted-foreground"
                        onClick={() => setShowPin(!showPin)}
                      >
                        {showPin ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                      </button>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      This is the PIN you set during registration
                    </p>
                  </div>
                  
                  <Button type="submit" className="w-full" disabled={loading}>
                    {loading ? (
                      <div className="flex items-center">
                        <svg className="animate-spin -ml-1 mr-3 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        Verifying...
                      </div>
                    ) : (
                      'Verify Identity'
                    )}
                  </Button>
                </form>
              </motion.div>
            )}

            {mode === 'access-granted' && (
              <motion.div
                key="access-granted"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.3 }}
              >
                {requestStatus === 'pending' ? (
                  <div className="text-center py-8">
                    <div className="w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center mx-auto mb-4">
                      <FileCheck className="w-8 h-8 text-primary" />
                    </div>
                    <h2 className="text-xl font-semibold mb-2">Request Sent Successfully</h2>
                    <p className="text-muted-foreground mb-4">
                      Your access request has been sent to the document owner.
                    </p>
                    <div className="flex items-center justify-center gap-2 text-primary mb-6">
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Waiting for owner's response...</span>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      You will be notified when the owner responds to your request.
                      Please keep this window open.
                    </p>
                  </div>
                ) : requestStatus === 'approved' ? (
                  <div className="space-y-6">
                    <div className="flex justify-between items-center">
                      <h2 className="text-xl font-semibold">Access Granted</h2>
                    </div>

                    {isLoadingDocuments ? (
                      <div className="flex items-center justify-center py-8">
                        <Loader2 className="w-6 h-6 animate-spin text-primary" />
                      </div>
                    ) : approvedDocuments.length > 0 ? (
                      <div className="grid gap-4">
                        {approvedDocuments.map((doc) => (
                          <Card key={doc.id} className="overflow-hidden">
                            <CardHeader className="p-4">
                              <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                  {getFileIcon(doc.type)}
                                  <div>
                                    <CardTitle className="text-base truncate max-w-[200px]">{doc.name}</CardTitle>
                                    <CardDescription className="text-xs">
                                      {(doc.size / 1024).toFixed(1)} KB
                                    </CardDescription>
                                  </div>
                                </div>
                                <DropdownMenu>
                                  <DropdownMenuTrigger asChild>
                                    <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                                      <MoreVertical className="h-4 w-4" />
                                    </Button>
                                  </DropdownMenuTrigger>
                                  <DropdownMenuContent align="end">
                                    <DropdownMenuItem onClick={() => handleView(doc)}>
                                      <Eye className="mr-2 h-4 w-4" />
                                      View
                                    </DropdownMenuItem>
                                    {hasDownloadPermission && (
                                      <DropdownMenuSub>
                                        <DropdownMenuSubTrigger>
                                          <Download className="mr-2 h-4 w-4" />
                                          Download
                                        </DropdownMenuSubTrigger>
                                        <DropdownMenuSubContent>
                                          <DropdownMenuRadioGroup value={downloadFormat} onValueChange={setDownloadFormat}>
                                            <DropdownMenuRadioItem value="original">
                                              Original Format
                                            </DropdownMenuRadioItem>
                                            <DropdownMenuRadioItem value="pdf">
                                              PDF
                                            </DropdownMenuRadioItem>
                                            <DropdownMenuRadioItem value="docx">
                                              Word (DOCX)
                                            </DropdownMenuRadioItem>
                                            <DropdownMenuRadioItem value="txt">
                                              Text (TXT)
                                            </DropdownMenuRadioItem>
                                          </DropdownMenuRadioGroup>
                                          <DropdownMenuItem onClick={() => handleDownload(doc.id.toString(), downloadFormat)}>
                                            <Download className="mr-2 h-4 w-4" />
                                            Download Now
                                          </DropdownMenuItem>
                                        </DropdownMenuSubContent>
                                      </DropdownMenuSub>
                                    )}
                                  </DropdownMenuContent>
                                </DropdownMenu>
                              </div>
                            </CardHeader>
                            <CardContent className="p-4 pt-0">
                              {/* Removed the buttons from here */}
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    ) : (
                      <div className="text-center py-8 text-muted-foreground">
                        No documents available
                      </div>
                    )}

                    <div className="flex justify-end">
                      <Button
                        variant="outline"
                        onClick={() => {
                          if (accessService.stopPolling) {
                            accessService.stopPolling();
                          }
                          setMode('initial');
                        }}
                      >
                        Exit
                      </Button>
                    </div>
                  </div>
                ) : requestStatus === 'denied' ? (
                  <div className="text-center py-8">
                    <div className="w-16 h-16 bg-destructive/10 rounded-full flex items-center justify-center mx-auto mb-4">
                      <XCircle className="w-8 h-8 text-destructive" />
                    </div>
                    <h2 className="text-xl font-semibold mb-2">Access Denied</h2>
                    <p className="text-muted-foreground mb-6">
                      Your request for document access has been denied by the document owner.
                    </p>
                    <Button
                      variant="outline"
                      onClick={() => {
                        if (accessService.stopPolling) {
                          accessService.stopPolling();
                        }
                        setMode('initial');
                      }}
                    >
                      Back to Home
                    </Button>
                  </div>
                ) : null}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </motion.div>

      {/* Document Viewer Modal */}
      {viewDocument && isViewDialogOpen && (
        <DocumentViewer
          documentId={viewDocument.id}
          fileName={viewDocument.name}
          fileType={viewDocument.type}
          documentSize={viewDocument.size}
          dateAdded={viewDocument.created_at}
          isOpen={isViewDialogOpen}
          onClose={handleCloseViewer}
          onDownload={() => handleDownload(viewDocument.id, 'original')}
          requestId={currentRequestId || undefined}
        />
      )}
    </div>
  );
};

export default Access;