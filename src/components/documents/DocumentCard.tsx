import React, { useState } from 'react';
import { File, MoreVertical, Download, Trash2, Edit, Eye, Check, X } from 'lucide-react';
import { motion } from 'framer-motion';
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
import { toast } from 'sonner';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '@/components/ui/alert-dialog';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import documentService from '@/services/document.service';
import DocumentViewer from './DocumentViewer';
import { Card, CardContent } from '@/components/ui/card';
import { FileText } from 'lucide-react';

export interface DocumentCardProps {
  id: string;
  name: string;
  type: string;
  size: string;
  dateAdded: string;
  onView?: () => void;
  onDownload?: () => void;
  onDelete?: () => void;
  onRename?: (id: string, newName: string) => void;
  isDeleting?: boolean;
  isRenaming?: boolean;
  isDownloading?: boolean;
  isViewing?: boolean;
  isDeletable?: boolean;
  isRenamable?: boolean;
  isDownloadable?: boolean;
  isViewable?: boolean;
  className?: string;
  style?: React.CSSProperties;
  children?: React.ReactNode;
}

const DocumentCard: React.FC<DocumentCardProps> = ({
  id,
  name,
  type,
  size,
  dateAdded,
  onView,
  onDownload,
  onDelete,
  onRename,
  isDeleting = false,
  isRenaming = false,
  isDownloading = false,
  isViewing = false,
  isDeletable = true,
  isRenamable = true,
  isDownloadable = true,
  isViewable = true,
  className = '',
  style,
  children
}) => {
  const [isHovering, setIsHovering] = useState(false);
  const [viewDialogOpen, setViewDialogOpen] = useState(false);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [downloadFormat, setDownloadFormat] = useState('original');
  const [newName, setNewName] = useState(name);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isDownloadingState, setIsDownloadingState] = useState(false);
  
  const handleDownload = async () => {
    try {
      setIsDownloadingState(true);
      await documentService.downloadDocument(id);
    } catch (error) {
      console.error('Error downloading document:', error);
      toast.error('Failed to download document');
    } finally {
      setIsDownloadingState(false);
    }
  };

  const handleDelete = async () => {
    if (onDelete) {
      try {
        await onDelete();
      } catch (error) {
        console.error('Error deleting document:', error);
      }
    }
  };

  const handleView = () => {
    setViewDialogOpen(true);
    onView();
  };

  const handleRename = () => {
    setRenameDialogOpen(true);
    setNewName(name);
  };

  const confirmRename = async () => {
    // Trim the name and check if it's empty
    const trimmedName = newName.trim();
    
    if (!trimmedName) {
      toast.error('Document name cannot be empty');
      return;
    }
    
    if (trimmedName === name) {
      setRenameDialogOpen(false);
      return;
    }

    if (onRename) {
      try {
        await onRename(id, trimmedName);
        setRenameDialogOpen(false);
      } catch (error: any) {
        console.error('Error renaming document:', error);
        toast.error(error.response?.data?.message || 'Failed to rename document');
        setNewName(name); // Reset to original name on error
      }
    }
  };

  const getFileIcon = (type: string) => {
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

  return (
    <Card className={`relative overflow-hidden transition-all hover:shadow-md ${className}`} style={style}>
      <CardContent className="p-4">
        <div className="flex items-start justify-between">
          <div className="flex items-start space-x-4">
            <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center">
              <FileText className="w-6 h-6 text-primary" />
            </div>
            <div className="flex-1 min-w-0">
              <h3 className="text-sm font-medium truncate">{name}</h3>
              <p className="text-xs text-muted-foreground mt-1">
                {getFileIcon(type)} • {size} • {dateAdded}
              </p>
            </div>
          </div>
          
          <div className="flex items-center">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="h-8 w-8 p-0">
                  <MoreVertical className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {isViewable && (
                  <DropdownMenuItem onClick={handleView}>
                    <Eye className="mr-2 h-4 w-4" />
                    View
                  </DropdownMenuItem>
                )}
                
                {isDownloadable && (
                  <DropdownMenuItem onClick={handleDownload} disabled={isDownloadingState}>
                    <Download className="mr-2 h-4 w-4" />
                    Download
                  </DropdownMenuItem>
                )}
                
                {isRenamable && (
                  <DropdownMenuItem onClick={handleRename}>
                    <Edit className="mr-2 h-4 w-4" />
                    Rename
                  </DropdownMenuItem>
                )}
                
                {isDeletable && (
                  <DropdownMenuItem onClick={handleDelete} className="text-red-500 focus:text-red-500">
                    <Trash2 className="mr-2 h-4 w-4" />
                    Delete
                  </DropdownMenuItem>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </CardContent>

      {/* View Document Dialog */}
      <Dialog open={viewDialogOpen} onOpenChange={setViewDialogOpen}>
        <DialogContent className="max-w-4xl h-[85vh] p-0">
          <div className="absolute right-4 top-4 z-10">
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 bg-white rounded-full shadow-sm hover:bg-gray-100"
              onClick={() => setViewDialogOpen(false)}
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
          <div className="h-full overflow-hidden">
            <DocumentViewer 
              documentId={id} 
              fileName={name}
              fileType={type}
              isOpen={viewDialogOpen}
              onClose={() => setViewDialogOpen(false)}
              nestedMode={true}
            />
          </div>
        </DialogContent>
      </Dialog>

      {/* Rename Dialog */}
      <Dialog open={renameDialogOpen} onOpenChange={setRenameDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename Document</DialogTitle>
          </DialogHeader>
          <Input
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="Enter new name"
            className="mt-4"
          />
          <div className="flex justify-end gap-2 mt-4">
            <Button variant="outline" onClick={() => setRenameDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={confirmRename}>
              Save
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </Card>
  );
};

export default DocumentCard;