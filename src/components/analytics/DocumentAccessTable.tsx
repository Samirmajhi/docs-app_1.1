import React, { useState, useMemo } from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Eye, Download, FileDown } from 'lucide-react';
import { formatDate } from '@/lib/utils';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { UserDocument } from '@/services/analytics';
import { toast } from 'react-hot-toast';
import { format as dateFormat } from 'date-fns';
import { jsPDF } from 'jspdf';
import 'jspdf-autotable';
import { autoTable } from 'jspdf-autotable';
import { exportDocumentAccessData } from '@/services/analytics';

// Extend jsPDF type to include autoTable
declare module 'jspdf' {
  interface jsPDF {
    autoTable: (options: any) => jsPDF;
  }
}

interface DocumentAccess {
  documentName: string;
  documentType: string;
  requesterName: string;
  requesterMobile: string;
  permissionLevel: 'view_only' | 'view_and_download';
  grantedAt: string;
}

interface DocumentAccessTableProps {
  accessRecords: DocumentAccess[];
  allDocuments: UserDocument[];
  isLoading: boolean;
  onExport?: (format: string) => void;
}

const DocumentAccessTable: React.FC<DocumentAccessTableProps> = ({
  accessRecords,
  allDocuments,
  isLoading,
  onExport
}) => {
  // State for filters
  const [selectedDocuments, setSelectedDocuments] = useState<string[]>([]);
  const [selectedPermission, setSelectedPermission] = useState<string>('all');
  const [startDate, setStartDate] = useState<Date | null>(null);
  const [endDate, setEndDate] = useState<Date | null>(null);

  // Filter records based on selected filters
  const filteredRecords = useMemo(() => {
    return accessRecords.filter(record => {
      const matchesDocument = selectedDocuments.length === 0 || selectedDocuments.includes(record.documentName);
      const matchesPermission = selectedPermission === 'all' || record.permissionLevel === selectedPermission;
      return matchesDocument && matchesPermission;
    });
  }, [accessRecords, selectedDocuments, selectedPermission]);

  // Handle export with filters
  const handleExport = async (format: 'csv' | 'pdf' | 'excel') => {
    try {
      // Build query parameters
      const params = new URLSearchParams();
      params.append('format', format);
      
      // Add date range if set
      if (startDate) {
        params.append('startDate', dateFormat(startDate, "yyyy-MM-dd'T'HH:mm:ss"));
      }
      if (endDate) {
        params.append('endDate', dateFormat(endDate, "yyyy-MM-dd'T'HH:mm:ss"));
      }
      
      // Add selected documents if any
      if (selectedDocuments.length > 0) {
        params.append('selectedDocuments', selectedDocuments.join(','));
      }
      
      // Add permission level if not 'all'
      if (selectedPermission !== 'all') {
        params.append('permissionLevel', selectedPermission);
      }

      const blob = await exportDocumentAccessData(format, params);

      if (format === 'pdf') {
        // For PDF, we get JSON data that needs to be converted to PDF
        const text = await blob.text();
        const data = JSON.parse(text);
        
        // Create PDF document
        const doc = new jsPDF();
        
        // Add title
        doc.setFontSize(16);
        doc.text('Document Access Report', 20, 20);
        
        // Add generation date
        doc.setFontSize(10);
        doc.text(`Generated on: ${dateFormat(new Date(), 'dd/MM/yyyy HH:mm')}`, 20, 30);
        
        // Add table
        doc.autoTable({
          head: [data.headers],
          body: data.data.map((row: any) => data.headers.map(header => row[header])),
          startY: 40,
          margin: { top: 20 },
          styles: { fontSize: 8 },
          headStyles: { fillColor: [41, 128, 185], textColor: 255 },
          alternateRowStyles: { fillColor: [245, 245, 245] }
        });
        
        // Save the PDF
        doc.save(`${data.filename}.pdf`);
      } else {
        // For CSV and Excel, download the file directly
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `document-access-report.${format === 'excel' ? 'xls' : format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }

      toast.success(`Successfully exported data as ${format.toUpperCase()}`);
    } catch (error) {
      console.error('Error exporting data:', error);
      toast.error('Failed to export data');
    }
  };

  const getPermissionBadge = (permission: string) => {
    switch (permission) {
      case 'view_only':
        return <Badge className="bg-blue-100 text-blue-800"><Eye className="h-3 w-3 mr-1" /> View Only</Badge>;
      case 'view_and_download':
        return <Badge className="bg-purple-100 text-purple-800"><Download className="h-3 w-3 mr-1" /> View & Download</Badge>;
      default:
        return null;
    }
  };

  if (isLoading) {
    return (
      <div className="flex justify-center py-8">
        <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin"></div>
      </div>
    );
  }

  if (!accessRecords || accessRecords.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        No document access records found.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          {/* Document Filter */}
          <div className="flex items-center gap-2">
            <Popover>
              <PopoverTrigger asChild>
                <Button variant="outline" className="h-8">
                  Documents ({selectedDocuments.length || 'All'})
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-80">
                <div className="space-y-4">
                  <div className="flex items-center gap-2">
                    <Checkbox 
                      checked={selectedDocuments.length === allDocuments.length}
                      onCheckedChange={(checked) => {
                        if (checked) {
                          setSelectedDocuments(allDocuments.map(doc => doc.name));
                        } else {
                          setSelectedDocuments([]);
                        }
                      }}
                    />
                    <Label>Select All</Label>
                  </div>
                  <ScrollArea className="h-[200px]">
                    <div className="space-y-2">
                      {allDocuments.map(doc => (
                        <div key={doc.id} className="flex items-center gap-2">
                          <Checkbox 
                            checked={selectedDocuments.includes(doc.name)}
                            onCheckedChange={(checked) => {
                              if (checked) {
                                setSelectedDocuments(prev => [...prev, doc.name]);
                              } else {
                                setSelectedDocuments(prev => prev.filter(d => d !== doc.name));
                              }
                            }}
                          />
                          <Label className="flex items-center gap-2">
                            <span>{doc.name}</span>
                          </Label>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </div>
              </PopoverContent>
            </Popover>
          </div>

          {/* Permission Level Filter */}
          <Select value={selectedPermission} onValueChange={setSelectedPermission}>
            <SelectTrigger className="w-[180px] h-8">
              <SelectValue placeholder="Permission Level" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Permissions</SelectItem>
              <SelectItem value="view_only">View Only</SelectItem>
              <SelectItem value="view_and_download">View & Download</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Export Button */}
        {onExport && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                <FileDown className="h-4 w-4 mr-2" />
                Export
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem onClick={() => handleExport('csv')}>
                Export as CSV
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleExport('excel')}>
                Export as Excel
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleExport('pdf')}>
                Export as PDF
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Document</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Requester</TableHead>
            <TableHead>Contact</TableHead>
            <TableHead>Permission</TableHead>
            <TableHead>Granted On</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filteredRecords.map((record, index) => (
            <TableRow key={index}>
              <TableCell className="font-medium">{record.documentName}</TableCell>
              <TableCell>{record.documentType}</TableCell>
              <TableCell>{record.requesterName}</TableCell>
              <TableCell>{record.requesterMobile}</TableCell>
              <TableCell>{getPermissionBadge(record.permissionLevel)}</TableCell>
              <TableCell>{formatDate(record.grantedAt)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
};

export default DocumentAccessTable;