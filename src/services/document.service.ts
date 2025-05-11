import api from './api';
import { toast } from 'sonner';
import axios from 'axios';

export interface Document {
  id: string;
  name: string;
  type: string;
  size: number;
  file_path: string;
  created_at: string;
  file_id: string;
}

export interface DocumentUploadResponse {
  message: string;
  document: Document;
}

// Backblaze B2 Configuration
const b2Config = {
  accountId: '0050526829e47e40000000003',
  applicationKey: 'K005llCKBSoscSaL/odeahd/NEC6puI',
  bucketId: '60253276a812996e94670e14',
  bucketName: 'secure-docs3963',
  apiUrl: 'https://api.backblazeb2.com'
};

// Keep track of uploads in progress to prevent duplicates
const uploadsInProgress = new Set<string>();

const documentService = {
  getDocuments: async (): Promise<Document[]> => {
    try {
      console.log('Fetching documents...');
      const response = await api.get('/documents');
      console.log('Documents response:', response.data);
      return response.data;
    } catch (error) {
      console.error('Error fetching documents:', error);
      console.error('Error details:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });
      toast.error('Failed to fetch documents. Please try again later.');
      return [];
    }
  },

  uploadDocument: async (file: File, customName?: string): Promise<DocumentUploadResponse> => {
    try {
      // Create a unique identifier for this upload using file name and size
      const uploadId = `${file.name}-${file.size}-${Date.now()}`;
      
      // Check if this file is already being uploaded
      if (uploadsInProgress.has(uploadId)) {
        console.log('Preventing duplicate upload of:', file.name);
        throw new Error('This file is already being uploaded');
      }
      
      // Mark this upload as in progress
      uploadsInProgress.add(uploadId);
      console.log('Starting upload of:', file.name, 'with ID:', uploadId);
      
      const formData = new FormData();
      formData.append('file', file);
      if (customName) {
        formData.append('customName', customName);
      }

      console.log('Upload request details:', {
        fileName: file.name,
        fileSize: file.size,
        fileType: file.type,
        customName,
        formDataEntries: Array.from(formData.entries())
      });

      const response = await api.post('/documents/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      // Upload completed successfully
      uploadsInProgress.delete(uploadId);
      console.log('Upload completed successfully for:', file.name);
      
      return response.data;
    } catch (error: any) {
      console.error('Error uploading document:', error);
      console.error('Error details:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status,
        headers: error.response?.headers
      });
      
      // Remove from in-progress uploads in case of error
      const uploadId = `${file.name}-${file.size}-${Date.now()}`;
      uploadsInProgress.delete(uploadId);
      
      // Check if it's a storage limit error
      if (error.response?.status === 413 && error.response?.data?.error === 'subscription_limit_exceeded') {
        console.log('Storage limit exceeded:', error.response.data.details);
        // Don't show toast here, let the component handle it
      } else {
        toast.error('Failed to upload document. Please try again.');
      }
      
      throw error;
    }
  },

  deleteDocument: async (id: string): Promise<{ message: string }> => {
    try {
      const response = await api.delete(`/documents/${id}`);
      return response.data;
    } catch (error) {
      console.error('Error deleting document:', error);
      toast.error('Failed to delete document. Please try again.');
      throw error;
    }
  },

  renameDocument: async (id: string, newName: string): Promise<{ message: string; document: Document }> => {
    try {
      console.log('Sending rename request:', { id, newName });
      const response = await api.put(`/documents/${id}/rename`, { newName });
      console.log('Rename response:', response.data);
      return response.data;
    } catch (error) {
      console.error('Error renaming document:', error);
      toast.error('Failed to rename document. Please try again.');
      throw error;
    }
  },

  downloadDocument: async (id: string, format: string = 'original'): Promise<void> => {
    try {
      // Get the file from our server
      const response = await api.get(`/documents/${id}/download`, {
        params: { format },
        responseType: 'blob'
      });

      // Create a blob URL and trigger download
      const blob = new Blob([response.data], { type: response.headers['content-type'] });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = response.headers['content-disposition']?.split('filename=')[1]?.replace(/"/g, '') || 'document';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      toast.success('Download started');
    } catch (error) {
      console.error('Error downloading document:', error);
      toast.error('Failed to download document. Please try again.');
      throw error;
    }
  },
  
  getDocumentForViewing: async (id: string): Promise<{ blob: Blob; contentType: string; permissionLevel: string }> => {
    try {
      if (!id) {
        throw new Error('Document ID is required');
      }

      const response = await api.get(`/documents/${id}/preview`, {
        responseType: 'blob',
        headers: {
          'Accept': '*/*'
        }
      });
      
      if (!response.data) {
        throw new Error('No document data received');
      }

      // Get content type from response or use a default
      const contentType = response.headers['content-type'] || 'application/octet-stream';
      
      // Get permission level from response headers
      const permissionLevel = response.headers['x-permission-level'] || 'view_and_download';
      
      return {
        blob: response.data,
        contentType,
        permissionLevel
      };
    } catch (error) {
      console.error('Error retrieving document for viewing:', error);
      throw error;
    }
  },
  
  // This helper function handles the actual download process
  initiateDownload: (blob: Blob, fileName: string): void => {
    // Get appropriate content type based on file extension or blob type
    let contentType = blob.type || 'application/octet-stream';
    
    if (!contentType || contentType === 'application/octet-stream') {
      // Try to determine content type from fileName if blob type is generic
      if (fileName.endsWith('.pdf')) {
        contentType = 'application/pdf';
      } else if (fileName.endsWith('.docx')) {
        contentType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
      } else if (fileName.endsWith('.txt')) {
        contentType = 'text/plain';
      } else if (fileName.endsWith('.jpg') || fileName.endsWith('.jpeg')) {
        contentType = 'image/jpeg';
      } else if (fileName.endsWith('.png')) {
        contentType = 'image/png';
      }
    }
    
    // Create a new blob with the correct content type
    const newBlob = new Blob([blob], { type: contentType });
    
    // Create download link
    const url = window.URL.createObjectURL(newBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    
    // Clean up
    setTimeout(() => {
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    }, 100);
  },

  // Check if upload would exceed storage limit
  checkStorageLimit: async (fileSize: number): Promise<{
    has_available_storage: boolean;
    storage_info: {
      used: number;
      limit: number;
      would_be_used: number;
      plan_name: string;
    };
  }> => {
    try {
      console.log('Checking storage limit for file size:', fileSize);
      // Ensure fileSize is a number and properly sent as JSON
      const response = await api.post('/documents/check-storage', { fileSize: Number(fileSize) });
      console.log('Storage check response:', response.data);
      return response.data;
    } catch (error) {
      console.error('Error checking storage limit:', error);
      
      // Check if this is a user not found error and handle auth issues
      if (error.response?.status === 404 && error.response?.data?.error === 'user_not_found') {
        toast.error('Your account information could not be found. Please log in again.');
        // Force logout
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        window.location.href = '/login';
        throw error;
      }
      
      // Return a safe default that lets the upload proceed
      // The server will still check storage when the actual upload happens
      console.log('Using default storage check result due to error');
      return {
        has_available_storage: true, // Optimistically allow the upload
        storage_info: {
          used: 0,
          limit: 5242880, // Default 5MB limit for free tier
          would_be_used: fileSize,
          plan_name: 'Unknown'
        }
      };
    }
  }
};

export default documentService;