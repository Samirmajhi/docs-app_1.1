import api from './api';
import { toast } from 'sonner';

export interface QRCodeResponse {
  message: string;
  qrCode: string;
  expiresAt: string;
  uniqueCode?: string;
  qrCodeUrl?: string;
}

export interface QRCodeValidation {
  message: string;
  qrCode: {
    id: number;
    ownerId: number;
    ownerName: string;
    hasAccessCode: boolean;
    documents: {
      id: number;
      name: string;
      type: string;
      size: number;
      created_at: string;
    }[];
  };
}

export interface AccessRequest {
  qrCodeId: number;
  requesterName: string;
  requesterMobile: string;
  requestedDocuments: string[];
}

const qrcodeService = {
  generateQRCode: async (): Promise<QRCodeResponse> => {
    try {
      console.log('Generating QR code without access code');
      const response = await api.post('/qrcode/generate');
      
      // Store the unique code in localStorage with a longer expiration time (30 days)
      if (response.data.uniqueCode) {
        const qrCodeData = {
          code: response.data.uniqueCode,
          expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days
          qrImage: response.data.qrCode // Store the QR image as well
        };
        localStorage.setItem('latestQRCode', JSON.stringify(qrCodeData));
        console.log('Stored QR code in localStorage:', qrCodeData);
      } else {
        // Generate a unique code if server didn't provide one
        const fallbackCode = `fallback-${Date.now()}`;
        const qrCodeData = {
          code: fallbackCode,
          expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days
          qrImage: response.data.qrCode
        };
        localStorage.setItem('latestQRCode', JSON.stringify(qrCodeData));
        
        // Add the uniqueCode to the response for consistency
        response.data.uniqueCode = fallbackCode;
        console.log('Generated fallback QR code and stored in localStorage:', qrCodeData);
      }
      
      return response.data;
    } catch (error) {
      console.error('Error generating QR code:', error);
      toast.error('Failed to generate QR code. Using backup method.');
      
      // Provide fallback QR code
      const fallbackCode = `fallback-${Date.now()}`;
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days
      
      // Create a base64 SVG QR code as fallback
      const fallbackQrCode = `data:image/svg+xml;base64,${btoa(`
        <svg width="200" height="200" xmlns="http://www.w3.org/2000/svg">
          <rect width="200" height="200" style="fill:white"/>
          <rect x="50" y="50" width="100" height="100" style="fill:black"/>
          <text x="50" y="170" font-family="Arial" font-size="12" fill="black">Mock QR Code</text>
        </svg>
      `)}`;
      
      // Store the fallback code
      const qrCodeData = {
        code: fallbackCode,
        expiresAt: expiresAt,
        qrImage: fallbackQrCode
      };
      localStorage.setItem('latestQRCode', JSON.stringify(qrCodeData));
      
      return {
        message: 'Generated fallback QR code',
        qrCode: fallbackQrCode,
        expiresAt: expiresAt,
        uniqueCode: fallbackCode
      };
    }
  },

  validateQRCode: async (code: string): Promise<QRCodeValidation> => {
    try {
      // Make sure code is trimmed and URL-safe
      const safeCode = encodeURIComponent(code.trim());
      console.log('Validating QR code:', safeCode, 'Original code:', code);
      
      // Try API validation first
      try {
        console.log('Attempting API validation for QR code');
        const response = await api.get(`/qrcode/validate/${safeCode}`);
        console.log('QR code validation response from API:', response.data);
        return response.data;
      } catch (apiError: any) {
        console.error('API validation error:', apiError);
        
        // Check if it's a network error
        if (apiError.code === 'ERR_NETWORK') {
          console.error('Network error during QR validation:', apiError);
          throw new Error('Network error. Please check your connection and try again.');
        }
        
        // Check if it's a server error
        if (apiError.response?.status === 500) {
          console.error('Server error during QR validation:', apiError);
          throw new Error('Server error. Please try again later.');
        }
        
        // If it's a 404, the QR code is invalid or expired
        if (apiError.response?.status === 404) {
          console.error('QR code not found or expired:', apiError);
          throw new Error('Invalid or expired QR code');
        }
        
        // For any other error, throw the original error
        throw apiError;
      }
    } catch (error: any) {
      console.error('Error validating QR code:', error);
      
      // Clean up the error message to remove any double http://
      let errorMessage = error.response?.data?.message || error.message || 'Failed to validate QR code';
      errorMessage = errorMessage.replace(/http:\/\/http:\/\//, 'http://');
      
      toast.error(errorMessage);
      throw error;
    }
  },

  requestAccess: async (request: AccessRequest): Promise<{ message: string; accessRequestId: string }> => {
    try {
      console.log('Requesting access with data:', request);
      const response = await api.post('/access/request', request);
      console.log('Access request response:', response.data);
      return response.data;
    } catch (error: any) {
      console.error('Error requesting access:', error);
      throw error; // Re-throw the error to be handled by the caller
    }
  },
  
  verifyOwner: async (mobileNumber: string, pin: string): Promise<any> => {
    try {
      console.log('Verifying owner with mobile:', mobileNumber, 'and PIN:', pin);
      
      // Try with actual API first
      try {
        console.log('Attempting API verification first');
        
        // Normalize the mobile number by:
        // 1. Removing all non-digit characters
        // 2. Adding country code if not present
        let normalizedMobile = mobileNumber.replace(/\D/g, '');
        if (!normalizedMobile.startsWith('977')) {
          normalizedMobile = '977' + normalizedMobile;
        }
        
        const response = await api.post('/access/verify', { 
          mobileNumber: normalizedMobile, 
          pin: pin.trim() 
        }, {
          headers: {
            'Authorization': '' 
          }
        });
        
        toast.success('Owner verification successful');
        return response.data;
      } catch (apiError) {
        console.log('API verification failed, falling back to local verification', apiError);
        
        // Fall back to local verification
        const storedUser = localStorage.getItem('user');
        console.log('Stored user from localStorage:', storedUser);
        
        if (storedUser) {
          const userData = JSON.parse(storedUser);
          console.log('User data for verification:', {
            storedMobile: userData.mobileNumber,
            providedMobile: mobileNumber,
            storedPin: userData.pin,
            providedPin: pin
          });
          
          // Normalize both stored and provided numbers
          const normalizedStoredMobile = userData.mobileNumber?.replace(/\D/g, '') || '';
          let normalizedProvidedMobile = mobileNumber.replace(/\D/g, '') || '';
          
          // Add country code to provided mobile if not present
          if (!normalizedProvidedMobile.startsWith('977')) {
            normalizedProvidedMobile = '977' + normalizedProvidedMobile;
          }
          
          console.log('Mobile number comparison:', {
            normalizedStored: normalizedStoredMobile,
            normalizedProvided: normalizedProvidedMobile
          });
          
          // Check if the provided mobile and PIN match
          const mobileMatches = normalizedStoredMobile === normalizedProvidedMobile;
          const pinMatches = userData.pin && pin && userData.pin.trim() === pin.trim();
          
          console.log('Verification results:', {
            mobileMatches,
            pinMatches
          });
          
          if (mobileMatches && pinMatches) {
            console.log('Local verification successful!');
            
            // Get documents from localStorage if available
            const documentsString = localStorage.getItem('documents');
            let documents = [];
            
            if (documentsString) {
              try {
                documents = JSON.parse(documentsString);
              } catch (e) {
                console.error('Error parsing documents:', e);
              }
            }
            
            toast.success('Owner verification successful');
            return {
              message: 'Owner verified successfully',
              documents: documents
            };
          } else {
            console.error('Local verification failed:', {
              mobileMatches,
              pinMatches
            });
            
            if (!mobileMatches) {
              toast.error('Mobile number does not match registration');
            } else if (!pinMatches) {
              toast.error('PIN does not match registration');
            } else {
              toast.error('Verification failed. Check your mobile number and PIN.');
            }
            
            throw new Error('Invalid credentials');
          }
        } else {
          console.log('No user found in localStorage');
          toast.error('No user data found for verification');
          throw new Error('No user data found');
        }
      }
    } catch (error: any) {
      console.error('Error verifying owner:', error);
      const errorMessage = error.response?.data?.message || 'Failed to verify as owner';
      toast.error(errorMessage);
      throw error;
    }
  },

  getDocuments: async (qrCodeId: number): Promise<{ documents: any[] }> => {
    try {
      const response = await api.get(`/qrcodes/${qrCodeId}/documents`);
      return response.data;
    } catch (error) {
      console.error('Error fetching documents:', error);
      throw error;
    }
  }
};

export default qrcodeService;