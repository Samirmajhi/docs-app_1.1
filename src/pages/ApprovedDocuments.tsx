import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Loader2, FileText, Download, Eye, MoreVertical } from 'lucide-react';
import { toast } from 'sonner';
import api from '@/services/api';
import DocumentCard from '../components/documents/DocumentCard';
import DocumentViewer from '../components/documents/DocumentViewer';
import documentService from '../services/document.service';
import { 
  DropdownMenu, 
  DropdownMenuContent, 
  DropdownMenuItem, 
  DropdownMenuTrigger,
  DropdownMenuSub,
  DropdownMenuSubTrigger,
  DropdownMenuSubContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem
} from '@/components/ui/dropdown-menu';
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger,
  SelectValue
} from '@/components/ui/select';

interface Document {
  id: string;
  name: string;
  type: string;
  size: string;
  dateAdded: string;
}

const ApprovedDocuments = () => {
  const { requestId } = useParams();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [documents, setDocuments] = useState<Document[]>([]);
  const [viewDocument, setViewDocument] = useState<Document | null>(null);
  const [isViewDialogOpen, setIsViewDialogOpen] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);
  const [downloadFormat, setDownloadFormat] = useState('original');

  useEffect(() => {
    const fetchApprovedDocuments = async () => {
      try {
        setLoading(true);
        const response = await api.get(`/access/requests/${requestId}/documents`);
        setDocuments(response.data.documents);
      } catch (err: any) {
        setError(err.response?.data?.message || 'Failed to fetch approved documents');
      } finally {
        setLoading(false);
      }
    };

    fetchApprovedDocuments();
  }, [requestId]);

  const handleView = async (doc: Document) => {
    try {
      setViewDocument(doc);
      setIsViewDialogOpen(true);
    } catch (error) {
      console.error('Error viewing document:', error);
      toast.error('Failed to view document');
    }
  };

  const handleDownload = async (docId: string, downloadFormat: string = 'original') => {
    try {
      const response = await fetch(`/api/documents/${docId}/download?format=${downloadFormat}`);
      if (!response.ok) {
        throw new Error('Failed to download document');
      }
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `document-${docId}.${downloadFormat}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Error downloading document:', error);
      toast.error('Failed to download document');
    }
  };

  const handleDelete = async (docId: string) => {
    try {
      await documentService.deleteDocument(docId);
      setDocuments(documents.filter(doc => doc.id !== docId));
      toast.success('Document deleted successfully');
    } catch (error) {
      console.error('Error deleting document:', error);
      toast.error('Failed to delete document');
    }
  };

  const handleRename = async (docId: string, newName: string) => {
    try {
      await documentService.renameDocument(docId, newName);
      setDocuments(documents.map(doc => 
        doc.id === docId ? { ...doc, name: newName } : doc
      ));
      toast.success('Document renamed successfully');
    } catch (error) {
      console.error('Error renaming document:', error);
      toast.error('Failed to rename document');
    }
  };

  const getFileType = (type: string) => {
    if (type.includes('pdf')) return 'PDF';
    if (type.includes('word') || type.includes('doc')) return type.includes('docx') ? 'DOCX' : 'DOC';
    if (type.includes('excel') || type.includes('sheet')) return type.includes('xlsx') ? 'XLSX' : 'XLS';
    if (type.includes('image')) {
      const ext = type.split('/').pop()?.toUpperCase();
      return ext || 'IMG';
    }
    if (type.includes('text/plain')) return 'TXT';
    if (type.includes('json')) return 'JSON';
    return 'FILE';
  };

  const getFileIcon = (type: string) => {
    const fileType = getFileType(type);
    switch (fileType) {
      case 'PDF':
        return <div className="w-8 h-8 bg-red-100 text-red-500 rounded-full flex items-center justify-center">PDF</div>;
      case 'DOC':
      case 'DOCX':
        return <div className="w-8 h-8 bg-blue-100 text-blue-500 rounded-full flex items-center justify-center">{fileType}</div>;
      case 'XLS':
      case 'XLSX':
        return <div className="w-8 h-8 bg-green-100 text-green-500 rounded-full flex items-center justify-center">{fileType}</div>;
      case 'TXT':
        return <div className="w-8 h-8 bg-gray-100 text-gray-500 rounded-full flex items-center justify-center">TXT</div>;
      case 'JSON':
        return <div className="w-8 h-8 bg-yellow-100 text-yellow-500 rounded-full flex items-center justify-center">JSON</div>;
      default:
        return <div className="w-8 h-8 bg-purple-100 text-purple-500 rounded-full flex items-center justify-center">{fileType}</div>;
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="w-8 h-8 animate-spin mx-auto mb-4 text-primary" />
          <p className="text-muted-foreground">Loading approved documents...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-red-500">
              <FileText className="w-6 h-6" />
              Error
            </CardTitle>
            <CardDescription>{error}</CardDescription>
          </CardHeader>
          <CardContent>
            <Button 
              onClick={() => navigate('/')}
              className="w-full"
            >
              Return to Home
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-4xl mx-auto">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-2xl font-semibold">Approved Documents</h1>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {documents.map((doc) => (
            <DocumentCard
              key={doc.id}
              id={doc.id}
              name={doc.name}
              type={doc.type}
              size={doc.size}
              dateAdded={doc.dateAdded}
              onView={() => handleView(doc)}
              onDownload={() => handleDownload(doc.id, downloadFormat)}
              onDelete={() => handleDelete(doc.id)}
              onRename={(newName) => handleRename(doc.id, newName)}
            />
          ))}
        </div>
      </div>

      {viewDocument && (
        <DocumentViewer
          documentId={viewDocument.id}
          fileName={viewDocument.name}
          fileType={viewDocument.type}
          documentSize={viewDocument.size}
          dateAdded={viewDocument.dateAdded}
          isOpen={isViewDialogOpen}
          onClose={() => setIsViewDialogOpen(false)}
          onDownload={() => handleDownload(viewDocument.id, downloadFormat)}
        />
      )}
    </div>
  );
};

export default ApprovedDocuments; 