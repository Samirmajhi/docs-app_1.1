import React from 'react';
import { File, PlusCircle } from 'lucide-react';
import DocumentCard, { DocumentCardProps } from './DocumentCard';
import { Button } from '@/components/ui/button';
import { motion } from 'framer-motion';

interface DocumentGridProps {
  documents: DocumentCardProps[];
  onAddNew: () => void;
  onDelete: (id: string) => void;
  onRename: (id: string, newName: string) => void;
}

const DocumentGrid = ({ documents, onAddNew, onDelete, onRename }: DocumentGridProps) => {
  if (documents.length === 0) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="flex flex-col items-center justify-center py-16 px-4 text-center"
      >
        <div className="w-20 h-20 rounded-full bg-primary/10 flex items-center justify-center mb-6">
          <File className="w-10 h-10 text-primary" />
        </div>
        <h3 className="text-xl font-medium mb-2">No documents yet</h3>
        <p className="text-muted-foreground mb-8 max-w-md">
          Start by uploading your first document. All your files will be securely stored and encrypted.
        </p>
        <Button onClick={onAddNew} className="flex items-center gap-2">
          <PlusCircle className="w-5 h-5" />
          <span>Upload Document</span>
        </Button>
      </motion.div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold">Your Documents</h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {documents.map((doc) => (
          <DocumentCard
            key={doc.id}
            {...doc}
            onDelete={() => onDelete(doc.id)}
            onRename={(id, newName) => onRename(id, newName)}
          />
        ))}
      </div>
    </div>
  );
};

export default DocumentGrid;
