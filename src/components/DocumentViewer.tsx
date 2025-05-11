import React, { useEffect, useState } from 'react';
import { Document } from '../services/document.service';
import { QRCodeValidation, AccessRequest } from '../services/qrcode.service';
import accessService from '../services/access.service';
import qrcodeService from '../services/qrcode.service';
import { toast } from 'sonner';

interface User {
  id: string;
  name: string;
  mobileNumber: string;
}

const DocumentViewer: React.FC = () => {
  const [document, setDocument] = useState<Document | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [hasAccess, setHasAccess] = useState(false);
  const [qrCode, setQRCode] = useState<QRCodeValidation | null>(null);

  const handleRequestAccess = async () => {
    try {
      if (!document || !user || !qrCode) return;

      // Create access request
      const accessRequest: AccessRequest = {
        qrCodeId: qrCode.qrCode.id,
        requesterName: user.name,
        requesterMobile: user.mobileNumber,
        requestedDocuments: [document.id]
      };

      // Request access through QR code service
      const response = await qrcodeService.requestAccess(accessRequest);
      
      // Poll for access status
      accessService.pollRequestStatus(response.accessRequestId, (status) => {
        if (status === 'approved') {
          setHasAccess(true);
          toast.success('Access granted successfully');
        } else if (status === 'denied') {
          toast.error('Access request denied');
        }
      });
    } catch (error) {
      console.error('Error requesting access:', error);
      toast.error('Failed to request access');
    }
  };

  useEffect(() => {
    // Fetch document, user, and QR code data
    // This is a placeholder and should be replaced with actual data fetching logic
    setDocument({ 
      id: '1',
      name: 'Sample Document',
      type: 'pdf',
      size: 1024,
      file_path: '/path/to/document',
      created_at: new Date().toISOString(),
      file_id: 'file123'
    });
    setUser({ 
      id: 'user123',
      name: 'John Doe',
      mobileNumber: '1234567890'
    });
  }, []);

  return (
    <div>
      {!hasAccess && (
        <button onClick={handleRequestAccess}>
          Request Access
        </button>
      )}
      {hasAccess && document && (
        <div>
          {/* Render document content here */}
          <h2>{document.name}</h2>
          {/* Add document viewer component */}
        </div>
      )}
    </div>
  );
};

export default DocumentViewer; 