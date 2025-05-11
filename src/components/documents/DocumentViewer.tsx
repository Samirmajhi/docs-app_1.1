import React, { useEffect, useState, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogClose, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Download, FileText, Image, ZoomIn, ZoomOut, X, Eye, RotateCw, RefreshCw, Maximize, ArrowDownToLine } from 'lucide-react';
import { Skeleton } from '@/components/ui/skeleton';
import documentService from '@/services/document.service';
import { toast } from 'sonner';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

export interface DocumentViewerProps {
  documentId: string;
  fileName?: string;
  fileType?: string;
  documentType?: string;
  documentSize?: string;
  dateAdded?: string;
  isOpen?: boolean;
  onClose?: () => void;
  onDownload?: () => Promise<void>;
  requestId?: string;
  nestedMode?: boolean;
}

const DocumentViewer = ({
  documentId,
  fileName,
  fileType,
  documentType,
  documentSize,
  dateAdded,
  isOpen = true,
  onClose = () => {},
  onDownload,
  nestedMode = false
}: DocumentViewerProps) => {
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [documentUrl, setDocumentUrl] = useState<string | null>(null);
  const [zoom, setZoom] = useState(100);
  const [rotation, setRotation] = useState(0);
  const [permissionLevel, setPermissionLevel] = useState<string | null>(null);
  const viewerRef = useRef<HTMLDivElement>(null);

  // Add keyboard event handler
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen, onClose]);

  const documentName = fileName || '';
  const documentTypeValue = fileType || documentType || '';

  const handleClose = () => {
    onClose();
  };

  useEffect(() => {
    const fetchDocument = async () => {
      try {
        if (!documentId) {
          throw new Error('Document ID is required');
        }

        setIsLoading(true);
        setError(null);
        // Use the existing service method or one that returns a URL
        const { blob, contentType, permissionLevel } = await documentService.getDocumentForViewing(documentId);
        
        // Create object URL for the document
        const url = URL.createObjectURL(blob);
        setDocumentUrl(url);
        setPermissionLevel(permissionLevel);
      } catch (err: any) {
        console.error('Error loading document:', err);
        setError(err.message || 'Failed to load document');
        toast.error(err.message || 'Failed to load document');
      } finally {
        setIsLoading(false);
      }
    };

    if (isOpen && documentId) {
      fetchDocument();
    }

    // Cleanup object URL when component unmounts or dialog closes
    return () => {
      if (documentUrl) {
        URL.revokeObjectURL(documentUrl);
      }
    };
  }, [documentId, isOpen]);

  const handleZoomIn = () => {
    setZoom(prev => Math.min(prev + 25, 300));
  };

  const handleZoomOut = () => {
    setZoom(prev => Math.max(prev - 25, 50));
  };

  const handleReset = () => {
    setZoom(100);
    setRotation(0);
  };

  const handleRotate = () => {
    setRotation(prev => (prev + 90) % 360);
  };

  const handleDownload = async () => {
    try {
      if (onDownload) {
        await onDownload();
      } else if (documentUrl) {
        // If no onDownload provided but we have a URL, create a download from the blob
        const a = document.createElement('a');
        a.href = documentUrl;
        a.download = documentName || 'document';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      } else {
        // Fall back to the service
        await documentService.downloadDocument(documentId);
      }
      toast.success('Download started');
    } catch (error) {
      console.error('Download error:', error);
      toast.error('Failed to download document');
    }
  };

  const isViewOnly = permissionLevel === 'view_only';

  const renderDocumentPreview = () => {
    if (isLoading) {
      return (
        <div className="flex items-center justify-center h-full">
          <Skeleton className="w-full h-full" />
        </div>
      );
    }

    if (error) {
      return (
        <div className="flex flex-col items-center justify-center h-full p-8">
          <div className="bg-red-50 p-8 rounded-lg border border-red-200 w-full max-w-md text-center">
            <FileText className="w-16 h-16 mx-auto text-red-500 mb-4" />
            <h3 className="text-xl font-medium mb-2">Error Loading Document</h3>
            <p className="text-red-600 mb-4">{error}</p>
            {!isViewOnly && (
              <Button onClick={handleDownload} variant="destructive">
                <Download className="mr-2 h-4 w-4" />
                Download to View
              </Button>
            )}
          </div>
        </div>
      );
    }

    if (documentTypeValue.includes('pdf')) {
      return (
        <div className="relative w-full h-full" ref={viewerRef}>
          <div 
            className="w-full h-full overflow-auto"
            style={{ 
              padding: zoom > 100 ? '20px' : '0'
            }}
          >
            <iframe
              src={`${documentUrl}#toolbar=0&navpanes=0&scrollbar=1&view=FitH&zoom=${zoom}`}
              className="w-full h-full"
              title={documentName}
              style={{
                transform: `scale(${zoom / 100}) rotate(${rotation}deg)`,
                transformOrigin: 'center',
                transition: 'transform 0.2s ease'
              }}
            />
          </div>
        </div>
      );
    } else if (documentTypeValue.includes('image/')) {
      return (
        <div 
          className="flex items-center justify-center w-full h-full overflow-auto p-4" 
          ref={viewerRef}
        >
          <img 
            src={documentUrl || ''} 
            alt={documentName} 
            style={{
              maxWidth: `${zoom}%`,
              maxHeight: '100%',
              transform: `rotate(${rotation}deg)`,
              transition: 'transform 0.2s ease'
            }} 
            className="object-contain"
          />
        </div>
      );
    } else {
      return (
        <div className="flex flex-col items-center justify-center h-full p-8">
          <div className="bg-gray-50 p-8 rounded-lg border border-gray-200 w-full max-w-md text-center">
            <FileText className="w-16 h-16 mx-auto text-primary mb-4" />
            <h3 className="text-xl font-medium mb-2 truncate">{documentName}</h3>
            <p className="text-muted-foreground mb-4">
              This document type cannot be previewed directly in the browser.
            </p>
            {isViewOnly ? (
              <Button disabled variant="outline">
                <Eye className="mr-2 h-4 w-4" />
                View Only Access
              </Button>
            ) : (
              <Button onClick={handleDownload}>
                <Download className="mr-2 h-4 w-4" />
                Download to View
              </Button>
            )}
          </div>
        </div>
      );
    }
  };

  // If the dialog is not open, don't render anything
  if (!isOpen) return null;

  // When in nested mode, render content directly without the Dialog wrapper
  if (nestedMode) {
    return (
      <div className="flex flex-col h-full">
        <div className="p-4 border-b flex items-center">
          <div className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            <h2 className="text-lg font-semibold truncate max-w-[300px]">{documentName}</h2>
            {isViewOnly && (
              <span className="ml-2 inline-flex items-center rounded-md bg-blue-50 px-2 py-1 text-xs font-medium text-blue-700 ring-1 ring-inset ring-blue-600/20">
                <Eye className="mr-1 h-3 w-3" /> View Only
              </span>
            )}
          </div>
        </div>
        
        {/* Document viewer toolbar */}
        <div className="p-2 border-b bg-muted/30 flex items-center justify-between">
          <div className="flex items-center">
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    onClick={handleZoomOut}
                    disabled={zoom <= 50}
                  >
                    <ZoomOut className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Zoom Out</TooltipContent>
              </Tooltip>
            </TooltipProvider>
            
            <span className="px-2 text-sm font-medium min-w-[60px] text-center">
              {zoom}%
            </span>
            
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    onClick={handleZoomIn}
                    disabled={zoom >= 300}
                  >
                    <ZoomIn className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Zoom In</TooltipContent>
              </Tooltip>
            </TooltipProvider>
            
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    onClick={handleRotate}
                  >
                    <RotateCw className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Rotate</TooltipContent>
              </Tooltip>
            </TooltipProvider>
            
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    onClick={handleReset}
                  >
                    <RefreshCw className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Reset View</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </div>
          
          {!isViewOnly && (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleDownload}
                    disabled={isLoading}
                    className="gap-1"
                  >
                    <ArrowDownToLine className="h-4 w-4" />
                    Download
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Download Document</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
        </div>
        
        <div className="flex-1 overflow-hidden">
          {renderDocumentPreview()}
        </div>
      </div>
    );
  }

  return (
    <Dialog 
      open={isOpen} 
      onOpenChange={(open) => {
        console.log("Dialog onOpenChange", open);
        if (!open) {
          onClose();
        }
      }}
    >
      <DialogContent 
        className="max-w-5xl h-[90vh] p-0"
      >
        <DialogHeader className="p-4 border-b">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileText className="h-5 w-5" />
              <DialogTitle className="text-lg truncate max-w-[300px]">{documentName}</DialogTitle>
              {isViewOnly && (
                <span className="ml-2 inline-flex items-center rounded-md bg-blue-50 px-2 py-1 text-xs font-medium text-blue-700 ring-1 ring-inset ring-blue-600/20">
                  <Eye className="mr-1 h-3 w-3" /> View Only
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="icon"
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  console.log("Close button clicked");
                  onClose();
                }}
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </DialogHeader>
        
        {/* Document viewer toolbar */}
        <div className="p-2 border-b bg-muted/30 flex items-center justify-between">
          <div className="flex items-center">
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    onClick={handleZoomOut}
                    disabled={zoom <= 50}
                  >
                    <ZoomOut className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Zoom Out</TooltipContent>
              </Tooltip>
            </TooltipProvider>
            
            <span className="px-2 text-sm font-medium min-w-[60px] text-center">
              {zoom}%
            </span>
            
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    onClick={handleZoomIn}
                    disabled={zoom >= 300}
                  >
                    <ZoomIn className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Zoom In</TooltipContent>
              </Tooltip>
            </TooltipProvider>
            
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    onClick={handleRotate}
                  >
                    <RotateCw className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Rotate</TooltipContent>
              </Tooltip>
            </TooltipProvider>
            
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    onClick={handleReset}
                  >
                    <RefreshCw className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Reset View</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </div>
          
          {!isViewOnly && (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleDownload}
                    disabled={isLoading}
                    className="gap-1"
                  >
                    <ArrowDownToLine className="h-4 w-4" />
                    Download
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Download Document</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
        </div>
        
        <div className="flex-1 h-[calc(90vh-10rem)] overflow-hidden">
          {renderDocumentPreview()}
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default DocumentViewer;