import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import Navbar from '@/components/layout/Navbar';
import DocumentUpload from '@/components/documents/DocumentUpload';
import DocumentGrid from '@/components/documents/DocumentGrid';
import { Button } from '@/components/ui/button';
import { X, Upload } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';
import { DocumentCardProps } from '@/components/documents/DocumentCard';
import documentService, { Document } from '@/services/document.service';

const Documents = () => {
  const [showUpload, setShowUpload] = useState(false);
  const queryClient = useQueryClient();

  // Query to fetch documents
  const { data: documents = [], isLoading } = useQuery({
    queryKey: ['documents'],
    queryFn: documentService.getDocuments,
  });

  // Format documents for the DocumentGrid component
  const formattedDocuments: DocumentCardProps[] = documents.map((doc: Document) => ({
    id: doc.id,
    name: doc.name,
    type: doc.type,
    size: `${Math.round(doc.size / 1024)} KB`,
    dateAdded: new Date(doc.created_at).toLocaleDateString('en-US', { 
      month: 'long',
      day: 'numeric', 
      year: 'numeric' 
    })
  }));

  // Mutation for document upload
  const uploadMutation = useMutation({
    mutationFn: (file: File) => documentService.uploadDocument(file),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['documents'] });
      setShowUpload(false);
      toast.success('Document uploaded successfully');
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.message || 'Failed to upload document');
    }
  });

  // Mutation for document deletion
  const deleteMutation = useMutation({
    mutationFn: (id: string) => documentService.deleteDocument(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['documents'] });
      toast.success('Document deleted successfully');
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.message || 'Failed to delete document');
    }
  });

  // Mutation for document rename
  const renameMutation = useMutation({
    mutationFn: ({ id, newName }: { id: string; newName: string }) => 
      documentService.renameDocument(id, newName),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['documents'] });
      toast.success('Document renamed successfully');
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.message || 'Failed to rename document');
    }
  });

  const handleAddDocument = () => {
    setShowUpload(true);
  };

  const handleDeleteDocument = (id: string) => {
    deleteMutation.mutate(id);
  };

  const handleRenameDocument = (id: string, newName: string) => {
    console.log('Renaming document:', { id, newName });
    renameMutation.mutate({ id, newName });
  };

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <main className="container mx-auto px-4 pt-24 pb-16">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center justify-between mb-8">
            <motion.h1 
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-3xl font-bold"
            >
              Your Documents
            </motion.h1>
            
            {!showUpload && (
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.2 }}
              >
                <Button 
                  onClick={handleAddDocument}
                  className="flex items-center gap-2"
                  size="lg"
                >
                  <Upload className="h-5 w-5" />
                  Upload Document
                </Button>
              </motion.div>
            )}
          </div>

          <AnimatePresence>
            {showUpload && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="bg-white rounded-xl p-6 shadow-sm border border-border mb-8 overflow-hidden"
              >
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-xl font-semibold">Upload New Document</h2>
                  <Button 
                    variant="ghost" 
                    size="icon"
                    onClick={() => setShowUpload(false)}
                  >
                    <X className="h-5 w-5" />
                  </Button>
                </div>
                <DocumentUpload onSuccess={() => {
                  queryClient.invalidateQueries({ queryKey: ['documents'] });
                  setShowUpload(false);
                }} />
              </motion.div>
            )}
          </AnimatePresence>

          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-16">
              <div className="w-16 h-16 rounded-full border-4 border-primary/30 border-t-primary animate-spin"></div>
              <p className="mt-4 text-muted-foreground">Loading your documents...</p>
            </div>
          ) : (
            <DocumentGrid 
              documents={formattedDocuments} 
              onAddNew={handleAddDocument} 
              onDelete={handleDeleteDocument}
              onRename={handleRenameDocument}
            />
          )}
        </div>
      </main>
    </div>
  );
};

export default Documents;