import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { 
  Loader2, 
  CheckCircle, 
  XCircle, 
  FileText, 
  User, 
  Calendar, 
  Edit, 
  Info,
  FileIcon,
  Clock,
  Phone,
  Eye,
  Download
} from 'lucide-react';
import { toast } from 'sonner';
import api from '@/services/api';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useAuth } from '@/context/AuthContext';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { formatFileSize } from '@/lib/utils';

interface RequestedDocument {
  id: string;
  name: string;
  type: string;
  size: number;
  selected: boolean;
}

interface AccessRequest {
  id: string;
  requesterName: string;
  requesterMobile: string;
  status: string;
  createdAt: string;
  documents: RequestedDocument[];
  isOwner: boolean;
}

const AccessRequestDetails = () => {
  const { requestId } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [request, setRequest] = useState<AccessRequest | null>(null);
  const [selectedDocs, setSelectedDocs] = useState<string[]>([]);
  const [processing, setProcessing] = useState(false);
  const [permissionLevel, setPermissionLevel] = useState<'view_only' | 'view_and_download'>('view_and_download');

  useEffect(() => {
    const fetchRequestDetails = async () => {
      try {
        setLoading(true);
        const response = await api.get(`/access/requests/${requestId}`);
        const requestData = response.data;
        
        // Initialize selected documents with all requested documents for owners
        const initialSelectedDocs = requestData.isOwner 
          ? requestData.documents.map((doc: any) => doc.id)
          : [];
        
        setRequest(requestData);
        setSelectedDocs(initialSelectedDocs);
      } catch (err: any) {
        if (err.response?.status === 404) {
          setError('Access request not found');
        } else {
          setError(err.response?.data?.message || 'Failed to fetch request details');
        }
      } finally {
        setLoading(false);
      }
    };

    fetchRequestDetails();
  }, [requestId]);

  const handleDocumentSelect = (docId: string) => {
    setSelectedDocs(prev => 
      prev.includes(docId) 
        ? prev.filter(id => id !== docId) 
        : [...prev, docId]
    );
  };

  const toggleAllDocuments = (selectAll: boolean) => {
    if (selectAll && request) {
      setSelectedDocs(request.documents.map(doc => doc.id));
    } else {
      setSelectedDocs([]);
    }
  };

  const handleAction = async (action: 'approve' | 'deny') => {
    if (action === 'approve' && selectedDocs.length === 0) {
      toast.error('Please select at least one document to approve');
      return;
    }

    try {
      setProcessing(true);
      if (action === 'approve') {
        await api.post(`/access/requests/${requestId}/approve`, {
          selectedDocuments: selectedDocs,
          permissionLevel: permissionLevel
        });
        
        toast.success(
          <div className="flex flex-col gap-1">
            <span className="font-semibold text-green-600">Request approved successfully</span>
            <span className="text-sm text-muted-foreground">
              {permissionLevel === 'view_only' 
                ? 'User will only be able to view documents'
                : 'User will be able to view and download documents'}
            </span>
          </div>
        );
      } else {
        await api.post(`/access/requests/${requestId}/deny`);
        toast.success('Request denied successfully');
      }
      
      // Refresh request details
      const updatedResponse = await api.get(`/access/requests/${requestId}`);
      setRequest(updatedResponse.data);
      
      navigate('/dashboard');
    } catch (error: any) {
      console.error('Error processing request:', error);
      toast.error(error.response?.data?.message || `Failed to ${action} request`);
    } finally {
      setProcessing(false);
    }
  };

  const getStatusBadge = (status: string) => {
    const statusConfig = {
      pending: { class: 'bg-yellow-100 text-yellow-800', text: 'Pending' },
      approved: { class: 'bg-green-100 text-green-800', text: 'Approved' },
      denied: { class: 'bg-red-100 text-red-800', text: 'Denied' }
    };
    const config = statusConfig[status as keyof typeof statusConfig] || statusConfig.pending;
    return <Badge variant="outline" className={config.class}>{config.text}</Badge>;
  };

  const getFileIcon = (type: string) => {
    if (type.includes('pdf')) {
      return <div className="w-10 h-10 bg-red-100 text-red-500 rounded-lg flex items-center justify-center font-medium">PDF</div>;
    } else if (type.includes('word') || type.includes('doc')) {
      return <div className="w-10 h-10 bg-blue-100 text-blue-500 rounded-lg flex items-center justify-center font-medium">DOC</div>;
    } else if (type.includes('image')) {
      return <div className="w-10 h-10 bg-purple-100 text-purple-500 rounded-lg flex items-center justify-center font-medium">IMG</div>;
    } else {
      return <div className="w-10 h-10 bg-gray-100 text-gray-500 rounded-lg flex items-center justify-center font-medium">FILE</div>;
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-b from-background to-muted/30">
        <div className="text-center">
          <Loader2 className="w-8 h-8 animate-spin mx-auto mb-4 text-primary" />
          <p className="text-muted-foreground">Loading request details...</p>
        </div>
      </div>
    );
  }

  if (error || !request) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-b from-background to-muted/30 p-4">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-red-500">
              <XCircle className="w-6 h-6" />
              Error
            </CardTitle>
            <CardDescription>{error || 'Request not found'}</CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={() => navigate('/dashboard')} className="w-full">Return to Dashboard</Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-background to-muted/30 py-8 px-4">
      <div className="max-w-4xl mx-auto space-y-6">
        {/* Header Card */}
        <Card className="border-none shadow-md">
          <CardHeader className="pb-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-primary/10 rounded-lg">
                  <FileText className="w-6 h-6 text-primary" />
                </div>
                <div>
                  <CardTitle>Document Access Request</CardTitle>
                  <CardDescription>Review and manage document access request</CardDescription>
                </div>
              </div>
              {getStatusBadge(request.status)}
            </div>
          </CardHeader>
        </Card>

        {/* Main Content Card */}
        <Card className="border-none shadow-md">
          <CardContent className="p-6 space-y-6">
            {/* Requester Information */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-card rounded-xl p-4 border shadow-sm">
                <div className="flex items-center gap-3">
                  <User className="w-5 h-5 text-primary" />
                  <div>
                    <p className="text-sm font-medium">Requester</p>
                    <p className="text-sm text-muted-foreground">{request.requesterName}</p>
                  </div>
                </div>
              </div>
              
              <div className="bg-card rounded-xl p-4 border shadow-sm">
                <div className="flex items-center gap-3">
                  <Phone className="w-5 h-5 text-primary" />
                  <div>
                    <p className="text-sm font-medium">Contact</p>
                    <p className="text-sm text-muted-foreground">{request.requesterMobile}</p>
                  </div>
                </div>
              </div>
              
              <div className="bg-card rounded-xl p-4 border shadow-sm">
                <div className="flex items-center gap-3">
                  <Clock className="w-5 h-5 text-primary" />
                  <div>
                    <p className="text-sm font-medium">Requested On</p>
                    <p className="text-sm text-muted-foreground">
                      {new Date(request.createdAt).toLocaleDateString()} at {new Date(request.createdAt).toLocaleTimeString()}
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <Separator />

            {/* Permission Level Selection - Only show for pending requests */}
            {request.status === 'pending' && request.isOwner && (
              <div className="space-y-3">
                <Label>Permission Level</Label>
                <Select
                  value={permissionLevel}
                  onValueChange={(value: 'view_only' | 'view_and_download') => setPermissionLevel(value)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="view_and_download">
                      <div className="flex items-center gap-2">
                        <Download className="h-4 w-4" />
                        <span>View & Download</span>
                      </div>
                    </SelectItem>
                    <SelectItem value="view_only">
                      <div className="flex items-center gap-2">
                        <Eye className="h-4 w-4" />
                        <span>View Only</span>
                      </div>
                    </SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-sm text-muted-foreground">
                  {permissionLevel === 'view_only' 
                    ? 'User will only be able to view documents online'
                    : 'User will be able to view and download documents'}
                </p>
              </div>
            )}

            {/* Document List */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold">Requested Documents</h3>
                {request.status === 'pending' && request.isOwner && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => toggleAllDocuments(selectedDocs.length !== request.documents.length)}
                  >
                    {selectedDocs.length === request.documents.length ? 'Deselect All' : 'Select All'}
                  </Button>
                )}
              </div>
              
              <div className="grid gap-3">
                {request.documents.map((doc) => (
                  <div 
                    key={doc.id} 
                    className="flex items-center p-4 bg-card rounded-xl border shadow-sm hover:shadow-md transition-shadow"
                  >
                    {request.status === 'pending' && request.isOwner && (
                      <Checkbox 
                        id={`doc-${doc.id}`}
                        checked={selectedDocs.includes(doc.id)}
                        onCheckedChange={() => handleDocumentSelect(doc.id)}
                        className="mr-4"
                      />
                    )}
                    <div className="flex items-center gap-4 flex-1">
                      {getFileIcon(doc.type)}
                      <div className="min-w-0 flex-1">
                        <p className="font-medium truncate">{doc.name}</p>
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                          <span>{doc.type}</span>
                          <span>•</span>
                          <span>{formatFileSize(doc.size)}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Action Buttons */}
            {request.status === 'pending' && request.isOwner && (
              <div className="flex items-center justify-end gap-3 pt-6">
                <Button
                  variant="outline"
                  onClick={() => navigate('/dashboard')}
                  disabled={processing}
                >
                  Cancel
                </Button>
                
                <Button
                  variant="destructive"
                  onClick={() => handleAction('deny')}
                  disabled={processing}
                >
                  {processing ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Processing...
                    </>
                  ) : (
                    <>
                      <XCircle className="w-4 h-4 mr-2" />
                      Deny Request
                    </>
                  )}
                </Button>

                <Button
                  variant="default"
                  onClick={() => handleAction('approve')}
                  disabled={processing || selectedDocs.length === 0}
                  className="bg-green-600 hover:bg-green-700"
                >
                  {processing ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Processing...
                    </>
                  ) : (
                    <>
                      <CheckCircle className="w-4 h-4 mr-2" />
                      Approve Request
                    </>
                  )}
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default AccessRequestDetails; 