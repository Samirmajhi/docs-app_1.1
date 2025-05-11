import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { format, subDays, endOfDay, startOfDay } from 'date-fns';
import Navbar from '@/components/layout/Navbar';
import {
  getAnalytics,
  getLatestAccessRequests,
  exportAnalyticsData,
  getDocumentAccessRecords,
  getAllUserDocuments,
  AnalyticsData,
  AccessRequestItem,
  DocumentAccessRecord,
  UserDocument
} from '@/services/analytics';
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
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Download, Calendar as CalendarIcon, Filter, ChevronRight, AlertCircle } from 'lucide-react';
import { Link } from 'react-router-dom';
import { toast } from 'sonner';
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import AccessRequestTable from '@/components/analytics/AccessRequestTable';
import DocumentAccessTable from '@/components/analytics/DocumentAccessTable';

const Analytics = () => {
  // Set default to show today's data only
  const today = new Date();
  const [startDate, setStartDate] = useState<Date | undefined>(startOfDay(today));
  const [endDate, setEndDate] = useState<Date | undefined>(endOfDay(today));
  const [status, setStatus] = useState<string | undefined>(undefined);
  const [page, setPage] = useState(1);
  const limit = 10;

  // Format date for API - properly format both start and end dates
  const formatDateForApi = (date?: Date, isEndDate: boolean = false) => {
    if (!date) return undefined;
    
    // For date ranges to work correctly, start date needs start of day, end date needs end of day
    const adjustedDate = isEndDate ? endOfDay(date) : startOfDay(date);
    // Include time component in the formatted date for precise filtering
    return format(adjustedDate, 'yyyy-MM-dd\'T\'HH:mm:ss');
  };

  const { 
    data: analytics, 
    isLoading: analyticsLoading, 
    error: analyticsError,
    refetch: refetchAnalytics
  } = useQuery<AnalyticsData>({
    queryKey: ['analytics', formatDateForApi(startDate), formatDateForApi(endDate, true)],
    queryFn: () => getAnalytics(formatDateForApi(startDate), formatDateForApi(endDate, true)),
    refetchOnWindowFocus: false
  });

  const { 
    data: accessRequests, 
    isLoading: requestsLoading, 
    error: requestsError,
    refetch: refetchRequests
  } = useQuery({
    queryKey: ['accessRequests', page, limit, formatDateForApi(startDate), formatDateForApi(endDate, true), status],
    queryFn: () => getLatestAccessRequests(
      page,
      limit,
      formatDateForApi(startDate),
      formatDateForApi(endDate, true),
      status
    ),
    refetchOnWindowFocus: false
  });

  const { 
    data: documentAccess,
    isLoading: accessLoading,
    error: accessError
  } = useQuery<DocumentAccessRecord[]>({
    queryKey: ['documentAccess', formatDateForApi(startDate), formatDateForApi(endDate, true)],
    queryFn: () => getDocumentAccessRecords(formatDateForApi(startDate), formatDateForApi(endDate, true)),
    refetchOnWindowFocus: false
  });

  const { 
    data: userDocuments,
    isLoading: documentsLoading
  } = useQuery<UserDocument[]>({
    queryKey: ['userDocuments'],
    queryFn: getAllUserDocuments,
    refetchOnWindowFocus: false
  });

  const handleDateChange = (type: 'start' | 'end', date?: Date) => {
    if (type === 'start') {
      // If start date is set after end date, adjust end date
      if (date && endDate && date > endDate) {
        setEndDate(date);
      }
      setStartDate(date ? startOfDay(date) : undefined);
    } else {
      // If end date is set before start date, adjust start date
      if (date && startDate && date < startDate) {
        setStartDate(date);
      }
      setEndDate(date ? endOfDay(date) : undefined);
    }
    // Reset to first page when filters change
    setPage(1);
    
    // Trigger refetch after state updates
    setTimeout(() => {
      refetchAnalytics();
      refetchRequests();
    }, 100);
  };

  const handleStatusChange = (value: string) => {
    setStatus(value === 'all' ? undefined : value);
    // Reset to first page when filters change
    setPage(1);
  };

  const handleExport = async (format: 'csv' | 'pdf' | 'excel') => {
    try {
      const blob = await exportAnalyticsData(
        format,
        formatDateForApi(startDate),
        formatDateForApi(endDate, true)
      );
      
      // Create a download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `analytics-export-${format}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      toast.success(`Analytics data exported as ${format.toUpperCase()}`);
    } catch (error) {
      toast.error('Failed to export analytics data');
      console.error('Export error:', error);
    }
  };

  const handleExportDocumentAccess = async (params: string) => {
    try {
      // Add date range to the params if they exist
      const searchParams = new URLSearchParams(params);
      if (startDate) {
        searchParams.append('startDate', formatDateForApi(startDate));
      }
      if (endDate) {
        searchParams.append('endDate', formatDateForApi(endDate));
      }

      const response = await fetch(`/api/analytics/document-access/export?${searchParams.toString()}`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
          // Add Accept header based on format
          Accept: searchParams.get('format') === 'pdf' ? 'application/json' : 'text/csv'
        }
      });

      if (!response.ok) {
        throw new Error('Failed to export data');
      }

      // Get the filename from the Content-Disposition header or use a default
      const contentDisposition = response.headers.get('Content-Disposition');
      const filenameMatch = contentDisposition?.match(/filename="?([^"]+)"?/);
      const filename = filenameMatch?.[1] || `document-permissions.${searchParams.get('format')}`;

      // Get the response as blob with correct type
      const format = searchParams.get('format');
      const contentType = format === 'excel' ? 'application/vnd.ms-excel' : 
                         format === 'pdf' ? 'application/json' : 
                         'text/csv';
      
      const blob = new Blob(
        [await response.text()], 
        { type: contentType + ';charset=utf-8' }
      );

      // Download the file
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      toast.success('Successfully exported data');
    } catch (error) {
      console.error('Export error:', error);
      toast.error('Failed to export data');
    }
  };

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

  if (analyticsLoading) {
    return (
      <div className="min-h-screen bg-background">
        <Navbar />
        <div className="flex items-center justify-center h-screen">
          <div className="w-16 h-16 border-4 border-primary/30 border-t-primary rounded-full animate-spin"></div>
        </div>
      </div>
    );
  }

  if (analyticsError) {
    return (
      <div className="min-h-screen bg-background">
        <Navbar />
        <main className="container mx-auto px-4 pt-24 pb-16">
          <Alert variant="destructive" className="mb-6">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>
              Failed to load analytics data. Please try again later.
            </AlertDescription>
          </Alert>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <main className="container mx-auto px-4 pt-24 pb-16">
        <div className="flex flex-col md:flex-row md:items-center justify-between mb-6">
          <h1 className="text-3xl font-bold">Analytics Dashboard</h1>
          
          <div className="flex gap-2 mt-4 md:mt-0">
            {/* Date Filter */}
            <Popover>
              <PopoverTrigger asChild>
                <Button variant="outline" className="flex items-center gap-2">
                  <CalendarIcon className="h-4 w-4" />
                  <span>Date Range</span>
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-auto p-0" align="end">
                <div className="flex flex-col sm:flex-row gap-2 p-3">
                  <div>
                    <p className="text-sm font-medium mb-1">Start Date</p>
                    <Calendar
                      mode="single"
                      selected={startDate}
                      onSelect={(date) => handleDateChange('start', date)}
                      initialFocus
                    />
                  </div>
                  <div>
                    <p className="text-sm font-medium mb-1">End Date</p>
                    <Calendar
                      mode="single"
                      selected={endDate}
                      onSelect={(date) => handleDateChange('end', date)}
                      initialFocus
                    />
                  </div>
                </div>
              </PopoverContent>
            </Popover>
            
            {/* Export Button */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" className="flex items-center gap-2">
                  <Download className="h-4 w-4" />
                  <span>Export</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
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
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <Card>
            <CardHeader>
              <CardTitle>Total Access Requests</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-bold">{analytics?.totalRequests || 0}</p>
            </CardContent>
          </Card>
          
          <Card>
            <CardHeader>
              <CardTitle>Approved Requests</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-bold text-green-600">{analytics?.approvedRequests || 0}</p>
            </CardContent>
          </Card>
          
          <Card>
            <CardHeader>
              <CardTitle>Total Document Scans</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-bold text-blue-600">{analytics?.totalScans || 0}</p>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 gap-4">
            <Card>
              <CardHeader>
                <CardTitle>Access Requests Over Time</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="h-[400px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={analytics?.requestsOverTime || []}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis 
                        dataKey="date" 
                        tickFormatter={(date) => format(new Date(date), 'MMM dd')}
                      />
                      <YAxis />
                      <Tooltip 
                        labelFormatter={(date) => format(new Date(date), 'MMM dd, yyyy')}
                      />
                      <Line 
                        type="monotone" 
                        dataKey="count" 
                        stroke="#8884d8" 
                        name="Requests"
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>

            <Tabs defaultValue="requests" className="w-full">
              <TabsList>
                <TabsTrigger value="requests">Access Requests</TabsTrigger>
                <TabsTrigger value="permissions">Document Permissions</TabsTrigger>
              </TabsList>
              
              <TabsContent value="requests">
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between">
                    <CardTitle>Latest Access Requests</CardTitle>
                    <Select 
                      value={status || 'all'} 
                      onValueChange={handleStatusChange}
                    >
                      <SelectTrigger className="w-[160px]">
                        <SelectValue placeholder="Filter by status" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Statuses</SelectItem>
                        <SelectItem value="pending">Pending</SelectItem>
                        <SelectItem value="approved">Approved</SelectItem>
                        <SelectItem value="denied">Denied</SelectItem>
                      </SelectContent>
                    </Select>
                  </CardHeader>
                  <CardContent>
                    {requestsError ? (
                      <Alert variant="destructive" className="mb-4">
                        <AlertCircle className="h-4 w-4" />
                        <AlertTitle>Error</AlertTitle>
                        <AlertDescription>
                          There was an error fetching the latest access requests.
                          Please try again later.
                        </AlertDescription>
                      </Alert>
                    ) : null}

                    <AccessRequestTable 
                      requests={accessRequests?.requests || []}
                      isLoading={requestsLoading}
                      page={page}
                      limit={limit}
                      totalItems={accessRequests?.total || 0}
                      onPageChange={setPage}
                    />
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="permissions">
                <Card>
                  <CardHeader>
                    <CardTitle>Document Access Permissions</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {accessError ? (
                      <Alert variant="destructive" className="mb-4">
                        <AlertCircle className="h-4 w-4" />
                        <AlertTitle>Error</AlertTitle>
                        <AlertDescription>
                          There was an error fetching the document access records.
                          Please try again later.
                        </AlertDescription>
                      </Alert>
                    ) : null}

                    <DocumentAccessTable 
                      accessRecords={documentAccess || []}
                      allDocuments={userDocuments || []}
                      isLoading={accessLoading || documentsLoading}
                      onExport={handleExportDocumentAccess}
                    />
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
        </div>
      </main>
    </div>
  );
};

export default Analytics; 