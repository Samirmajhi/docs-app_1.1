import React, { useState, useEffect } from 'react';
import { format } from 'date-fns';
import { useNavigate } from 'react-router-dom';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ChevronRight, CheckCircle, XCircle, Eye, Download, Eye as ViewIcon, FileText } from 'lucide-react';
import { 
  AccessRequestItem, 
  AccessRequestDetails,
  approveAccessRequest, 
  denyAccessRequest,
  getAccessRequestDetails
} from '@/services/analytics';
import { toast } from 'sonner';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { formatBytes } from "@/lib/utils";

interface AccessRequestTableProps {
  requests: AccessRequestItem[];
  isLoading: boolean;
  page: number;
  limit: number;
  totalItems: number;
  onPageChange: (page: number) => void;
}

const AccessRequestTable: React.FC<AccessRequestTableProps> = ({
  requests,
  isLoading,
  page,
  limit,
  totalItems,
  onPageChange,
}) => {
  const navigate = useNavigate();
  const [selectedRequestId, setSelectedRequestId] = useState<string | null>(null);
  const [dialogAction, setDialogAction] = useState<'approve' | 'deny' | null>(null);
  const [processingId, setProcessingId] = useState<string | null>(null);
  const [permissionLevel, setPermissionLevel] = useState<'view_only' | 'view_and_download'>('view_and_download');
  const [requestDetails, setRequestDetails] = useState<AccessRequestDetails | null>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [selectedDocuments, setSelectedDocuments] = useState<string[]>([]);
  
  // Reset states when dialog closes
  useEffect(() => {
    if (!dialogAction) {
      setRequestDetails(null);
      setSelectedDocuments([]);
    }
  }, [dialogAction]);
  
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'approved':
        return <Badge className="bg-green-100 text-green-800">Approved</Badge>;
      case 'denied':
        return <Badge className="bg-red-100 text-red-800">Denied</Badge>;
      case 'pending':
      default:
        return <Badge className="bg-yellow-100 text-yellow-800">Pending</Badge>;
    }
  };
  
  const getPermissionBadge = (permission?: string) => {
    switch (permission) {
      case 'view_only':
        return <Badge className="bg-blue-100 text-blue-800"><ViewIcon className="h-3 w-3 mr-1" /> View Only</Badge>;
      case 'view_and_download':
      default:
        return <Badge className="bg-purple-100 text-purple-800"><Download className="h-3 w-3 mr-1" /> View & Download</Badge>;
    }
  };

  const handleViewDetails = (id: string) => {
    navigate(`/access-request/${id}`);
  };
  
  const fetchRequestDetails = async (requestId: string) => {
    setLoadingDetails(true);
    try {
      const details = await getAccessRequestDetails(requestId);
      setRequestDetails(details);
      // Select all documents by default
      setSelectedDocuments(details.documents.map(doc => doc.id));
    } catch (error) {
      console.error('Error fetching request details:', error);
      toast.error('Failed to fetch request details');
    } finally {
      setLoadingDetails(false);
    }
  };
  
  const handleApprove = async () => {
    if (!selectedRequestId) return;
    
    setProcessingId(selectedRequestId);
    try {
      if (selectedDocuments.length === 0) {
        toast.error('Please select at least one document to approve');
        return;
      }
      
      await approveAccessRequest(selectedRequestId, selectedDocuments, permissionLevel);
      toast.success(`Access request approved with ${permissionLevel === 'view_only' ? 'view-only' : 'view and download'} permissions`);
      // Reload the page or refetch data
      window.location.reload();
    } catch (error) {
      console.error('Error approving request:', error);
      toast.error('Failed to approve access request');
    } finally {
      setProcessingId(null);
      setSelectedRequestId(null);
      setDialogAction(null);
    }
  };
  
  const handleDeny = async () => {
    if (!selectedRequestId) return;
    
    setProcessingId(selectedRequestId);
    try {
      await denyAccessRequest(selectedRequestId);
      toast.success('Access request denied successfully');
      // Reload the page or refetch data
      window.location.reload();
    } catch (error) {
      console.error('Error denying request:', error);
      toast.error('Failed to deny access request');
    } finally {
      setProcessingId(null);
      setSelectedRequestId(null);
      setDialogAction(null);
    }
  };
  
  const openDialog = async (id: string, action: 'approve' | 'deny') => {
    setSelectedRequestId(id);
    setDialogAction(action);
    
    // Reset permission level to default for new approval dialog
    if (action === 'approve') {
      setPermissionLevel('view_and_download');
      // Fetch request details to get documents
      await fetchRequestDetails(id);
    }
  };
  
  const toggleDocumentSelection = (docId: string) => {
    setSelectedDocuments(prev => {
      if (prev.includes(docId)) {
        return prev.filter(id => id !== docId);
      } else {
        return [...prev, docId];
      }
    });
  };
  
  const toggleAllDocuments = (selectAll: boolean) => {
    if (selectAll && requestDetails) {
      setSelectedDocuments(requestDetails.documents.map(doc => doc.id));
    } else {
      setSelectedDocuments([]);
    }
  };
  
  if (isLoading) {
    return (
      <div className="flex justify-center py-8">
        <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin"></div>
      </div>
    );
  }
  
  if (!requests || requests.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        No access requests found for the selected criteria.
      </div>
    );
  }

  return (
    <div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Requester</TableHead>
            <TableHead>Contact</TableHead>
            <TableHead>Date</TableHead>
            <TableHead>Documents</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Permission</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {requests.map((request) => (
            <TableRow key={request.id}>
              <TableCell className="font-medium">{request.requesterName}</TableCell>
              <TableCell>{request.requesterMobile}</TableCell>
              <TableCell>{format(new Date(request.createdAt), 'MMM dd, yyyy')}</TableCell>
              <TableCell>{request.documentsCount}</TableCell>
              <TableCell>{getStatusBadge(request.status)}</TableCell>
              <TableCell>
                {request.status === 'approved' && getPermissionBadge(request.permissionLevel)}
              </TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-2">
                  {request.status === 'pending' && (
                    <>
                      <Button 
                        variant="outline" 
                        size="sm"
                        className="text-green-600 hover:text-green-700 hover:bg-green-50"
                        disabled={!!processingId}
                        onClick={() => openDialog(request.id, 'approve')}
                      >
                        <CheckCircle className="h-4 w-4 mr-1" />
                        <span className="sr-only md:not-sr-only md:inline-block">Approve</span>
                      </Button>
                      <Button 
                        variant="outline" 
                        size="sm"
                        className="text-red-600 hover:text-red-700 hover:bg-red-50"
                        disabled={!!processingId}
                        onClick={() => openDialog(request.id, 'deny')}
                      >
                        <XCircle className="h-4 w-4 mr-1" />
                        <span className="sr-only md:not-sr-only md:inline-block">Deny</span>
                      </Button>
                    </>
                  )}
                  {/* Only show View button for approved/denied requests */}
                  {request.status !== 'pending' && (
                    <Button 
                      variant="ghost" 
                      size="sm"
                      onClick={() => handleViewDetails(request.id)}
                    >
                      <Eye className="h-4 w-4 mr-1" />
                      <span className="sr-only md:not-sr-only md:inline-block">View</span>
                    </Button>
                  )}
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      
      {totalItems > limit && (
        <div className="flex justify-end items-center gap-2 mt-4">
          <Button 
            variant="outline" 
            size="sm"
            disabled={page === 1}
            onClick={() => onPageChange(page - 1)}
          >
            Previous
          </Button>
          <span className="text-sm text-muted-foreground">
            Page {page} of {Math.ceil(totalItems / limit)}
          </span>
          <Button 
            variant="outline" 
            size="sm"
            disabled={page >= Math.ceil(totalItems / limit)}
            onClick={() => onPageChange(page + 1)}
          >
            Next
          </Button>
        </div>
      )}
      
      {/* Confirmation Dialog */}
      <AlertDialog open={!!dialogAction} onOpenChange={(open) => !open && setDialogAction(null)}>
        <AlertDialogContent className="max-w-2xl">
          <AlertDialogHeader>
            <AlertDialogTitle>
              {dialogAction === 'approve' ? 'Approve Access Request' : 'Deny Access Request'}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {dialogAction === 'approve' 
                ? 'Select the documents you want to approve and the permission level for this access request.'
                : 'Are you sure you want to deny this access request? The requester will not be able to access any documents.'}
            </AlertDialogDescription>
          </AlertDialogHeader>
          
          {dialogAction === 'approve' && (
            <div className="py-4">
              {loadingDetails ? (
                <div className="flex justify-center py-8">
                  <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin"></div>
                </div>
              ) : (
                <>
                  {/* Document Selection */}
                  {requestDetails && (
                    <div className="mb-6">
                      <div className="flex items-center justify-between mb-2">
                        <Label className="text-sm font-medium">Select Documents</Label>
                        <div className="flex items-center space-x-2">
                          <Checkbox 
                            id="select-all"
                            checked={selectedDocuments.length === requestDetails.documents.length && requestDetails.documents.length > 0}
                            onCheckedChange={(checked) => toggleAllDocuments(!!checked)}
                          />
                          <Label htmlFor="select-all" className="text-xs">Select All</Label>
                        </div>
                      </div>
                      
                      <div className="border rounded-md overflow-hidden">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead className="w-[30px]">Select</TableHead>
                              <TableHead>Name</TableHead>
                              <TableHead>Type</TableHead>
                              <TableHead>Size</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {requestDetails.documents.map(doc => (
                              <TableRow key={doc.id}>
                                <TableCell>
                                  <Checkbox 
                                    checked={selectedDocuments.includes(doc.id)}
                                    onCheckedChange={() => toggleDocumentSelection(doc.id)}
                                  />
                                </TableCell>
                                <TableCell className="flex items-center gap-2">
                                  <FileText className="h-4 w-4 text-muted-foreground" />
                                  <span className="truncate">{doc.name}</span>
                                </TableCell>
                                <TableCell>{doc.type.split('/')[1]?.toUpperCase() || doc.type}</TableCell>
                                <TableCell>{formatBytes(doc.size)}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                      
                      {selectedDocuments.length === 0 && (
                        <p className="text-xs text-red-500 mt-1">
                          Please select at least one document to approve
                        </p>
                      )}
                    </div>
                  )}
                  
                  {/* Permission Level Selection */}
                  <Label htmlFor="permission-level" className="text-sm font-medium mb-2 block">
                    Permission Level
                  </Label>
                  <Select
                    value={permissionLevel}
                    onValueChange={(value) => setPermissionLevel(value as 'view_only' | 'view_and_download')}
                  >
                    <SelectTrigger id="permission-level" className="w-full">
                      <SelectValue placeholder="Select permission level" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="view_only">
                        <div className="flex items-center">
                          <ViewIcon className="h-4 w-4 mr-2" />
                          <span>View Only</span>
                        </div>
                      </SelectItem>
                      <SelectItem value="view_and_download">
                        <div className="flex items-center">
                          <Download className="h-4 w-4 mr-2" />
                          <span>View and Download</span>
                        </div>
                      </SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground mt-1">
                    {permissionLevel === 'view_only' 
                      ? 'Requester will only be able to view documents without downloading them'
                      : 'Requester will be able to both view and download the documents'}
                  </p>
                </>
              )}
            </div>
          )}
          
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction 
              onClick={dialogAction === 'approve' ? handleApprove : handleDeny}
              className={dialogAction === 'approve' ? 'bg-green-600 hover:bg-green-700' : 'bg-red-600 hover:bg-red-700'}
              disabled={dialogAction === 'approve' && (loadingDetails || selectedDocuments.length === 0)}
            >
              {dialogAction === 'approve' ? 'Approve' : 'Deny'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
};

export default AccessRequestTable; 