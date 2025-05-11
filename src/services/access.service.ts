import api from './api';

export interface AccessRequest {
  id: string;
  status: 'pending' | 'approved' | 'denied' | 'modified';
  documents: any[];
  // Add other fields as needed
}

class AccessService {
  private pollingInterval: NodeJS.Timeout | null = null;

  async getRequestStatus(requestId: string): Promise<AccessRequest> {
    const response = await api.get(`/access/requests/${requestId}`);
    return response.data;
  }

  async pollRequestStatus(
    requestId: string,
    onStatusChange: (status: 'pending' | 'approved' | 'denied' | 'modified') => void,
    interval: number = 5000
  ): Promise<void> {
    // Clear any existing polling
    this.stopPolling();

    // Start new polling
    this.pollingInterval = setInterval(async () => {
      try {
        const status = await this.getRequestStatus(requestId);
        onStatusChange(status.status);
        
        // Stop polling if request is no longer pending
        if (status.status !== 'pending') {
          this.stopPolling();
        }
      } catch (error) {
        console.error('Error polling request status:', error);
        this.stopPolling();
      }
    }, interval);
  }

  stopPolling(): void {
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
      this.pollingInterval = null;
    }
  }

  async downloadDocument(requestId: string, documentId: string, format: string): Promise<Blob> {
    const response = await api.get(`/documents/${documentId}/download`, {
      params: { format },
      responseType: 'blob'
    });
    return response.data;
  }

  async getDocumentAccess(requestId: string): Promise<{ documents: any[], permissionLevel?: string }> {
    const response = await api.get(`/access/requests/${requestId}/documents`);
    return response.data;
  }
}

export default new AccessService(); 