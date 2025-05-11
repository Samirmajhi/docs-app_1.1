import api from './api';

export interface AnalyticsData {
  totalRequests: number;
  approvedRequests: number;
  totalScans: number;
  requestsOverTime: Array<{
    date: string;
    count: number;
  }>;
  requestStatus: Array<{
    status: string;
    count: number;
  }>;
  scansOverTime: Array<{
    date: string;
    count: number;
  }>;
}

export interface AccessRequestItem {
  id: string;
  requesterName: string; 
  requesterMobile: string;
  status: 'pending' | 'approved' | 'denied';
  createdAt: string;
  documentsCount: number;
  permissionLevel?: 'view_only' | 'view_and_download';
}

export interface AccessRequestDetails {
  id: string;
  requesterName: string;
  requesterMobile: string;
  status: 'pending' | 'approved' | 'denied';
  createdAt: string;
  isOwner: boolean;
  permissionLevel?: 'view_only' | 'view_and_download';
  documents: Array<{
    id: string;
    name: string;
    type: string;
    size: number;
  }>;
}

export interface DocumentAccessRecord {
  documentName: string;
  documentType: string;
  requesterName: string;
  requesterMobile: string;
  permissionLevel: 'view_only' | 'view_and_download';
  grantedAt: string;
}

export interface UserDocument {
  id: string;
  name: string;
  type: string;
}

export const getAnalytics = async (startDate?: string, endDate?: string): Promise<AnalyticsData> => {
  const params: Record<string, string> = {};
  if (startDate) params.startDate = startDate;
  if (endDate) params.endDate = endDate;
  
  const response = await api.get('/analytics', { params });
  return response.data;
};

export const getLatestAccessRequests = async (
  page: number = 1,
  limit: number = 10,
  startDate?: string,
  endDate?: string,
  status?: string
): Promise<{ requests: AccessRequestItem[], total: number }> => {
  const params: Record<string, string | number> = { page, limit };
  if (startDate) params.startDate = startDate;
  if (endDate) params.endDate = endDate;
  if (status) params.status = status;
  
  const response = await api.get('/access-requests/latest', { params });
  return response.data;
};

export const getAccessRequestDetails = async (requestId: string): Promise<AccessRequestDetails> => {
  const response = await api.get(`/access/requests/${requestId}`);
  return response.data;
};

export const exportAnalyticsData = async (
  format: 'csv' | 'pdf' | 'excel',
  startDate?: string,
  endDate?: string
): Promise<Blob> => {
  const params: Record<string, string> = { format };
  if (startDate) params.startDate = startDate;
  if (endDate) params.endDate = endDate;
  
  const response = await api.get('/analytics/export', {
    params,
    responseType: 'blob'
  });
  
  return response.data;
};

// Access request functions
export const approveAccessRequest = async (
  requestId: string, 
  selectedDocuments?: string[],
  permissionLevel?: 'view_only' | 'view_and_download'
): Promise<any> => {
  const response = await api.post(`/access/requests/${requestId}/approve`, {
    selectedDocuments,
    permissionLevel
  });
  return response.data;
};

export const denyAccessRequest = async (requestId: string): Promise<any> => {
  const response = await api.post(`/access/requests/${requestId}/deny`);
  return response.data;
};

export const getDocumentAccessRecords = async (
  startDate?: string,
  endDate?: string
): Promise<DocumentAccessRecord[]> => {
  const params: Record<string, string> = {};
  if (startDate) params.startDate = startDate;
  if (endDate) params.endDate = endDate;
  
  const response = await api.get('/analytics/document-access', { params });
  return response.data;
};

export const getAllUserDocuments = async (): Promise<UserDocument[]> => {
  const response = await api.get('/documents');
  return response.data;
};

export const exportDocumentAccessData = async (
  format: 'csv' | 'pdf' | 'excel',
  params: URLSearchParams
): Promise<Blob> => {
  const response = await api.get(`/analytics/document-access/export?${params.toString()}`, {
    responseType: 'blob',
    headers: {
      'Accept': format === 'pdf' ? 'application/json' : 
                format === 'excel' ? 'application/vnd.ms-excel' : 
                'text/csv'
    }
  });
  
  return response.data;
};