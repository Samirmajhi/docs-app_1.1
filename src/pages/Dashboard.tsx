import React, { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FileText, Upload, QrCode, User, ArrowRight, Crown, ChevronRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import Navbar from '@/components/layout/Navbar';
import { motion } from 'framer-motion';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';
import documentService from '@/services/document.service';
import subscriptionService from '@/services/subscription.service';
import SubscriptionManager from '@/components/SubscriptionManager';
import { Card, CardContent } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import eventBus from '@/utils/eventBus';
import { useQueryClient } from '@tanstack/react-query';

const formatStorage = (bytes: number): string => {
  const mb = bytes / (1024 * 1024);
  return `${mb.toFixed(1)} MB`;
};

const Dashboard = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [stats, setStats] = useState({
    documents: 0,
    storage: '0 MB',
    shared: 0
  });

  // Fetch documents
  const { data: documents = [] } = useQuery({
    queryKey: ['documents'],
    queryFn: documentService.getDocuments,
    staleTime: 60000, // 1 minute
    retry: 3,
    retryDelay: 1000
  });

  // Fetch subscription data with more generous retry
  const { data: subscription, isError: subError, isLoading: subLoading, refetch: refetchSubscription } = useQuery({
    queryKey: ['subscription'],
    queryFn: async () => {
      try {
        // Try to get subscription data from service
        const data = await subscriptionService.getCurrentSubscription();
        console.log('Subscription query function result (raw):', data);
        
        // Ensure we're dealing with numbers for numeric properties
        const normalizedData = {
          ...data,
          id: typeof data.id === 'string' ? parseInt(data.id, 10) : data.id,
          storage_limit: typeof data.storage_limit === 'string' ? 
            parseInt(data.storage_limit, 10) : 
            (typeof data.storage_limit === 'number' ? data.storage_limit : 5 * 1024 * 1024),
          price: typeof data.price === 'string' ? 
            parseFloat(data.price) : 
            (typeof data.price === 'number' ? data.price : 0)
        };
        
        console.log('Subscription query function result (normalized):', normalizedData);
        return normalizedData;
      } catch (error) {
        console.error('Error in subscription query function:', error);
        // Return default data on error
        return {
          id: 1,
          name: 'Free',
          storage_limit: 5 * 1024 * 1024, // 5MB in bytes
          price: 0,
          features: ['5MB Storage', 'Basic Document Management']
        };
      }
    },
    staleTime: 60000, // 1 minute
    refetchOnWindowFocus: true,
    refetchOnMount: true,
    retry: 3,
    retryDelay: 1000
  });

  // Fetch storage usage with more generous retry
  const { data: storageUsage, isError: storageError, isLoading: storageLoading, refetch: refetchStorage } = useQuery({
    queryKey: ['storage'],
    queryFn: async () => {
      try {
        // Try to get storage data from service
        const data = await subscriptionService.getStorageUsage();
        console.log('Storage query function result (raw):', data);
        
        // Ensure we're dealing with numbers
        const normalizedData = {
          used: typeof data.used === 'string' ? parseInt(data.used, 10) : (typeof data.used === 'number' ? data.used : 0),
          limit: typeof data.limit === 'string' ? parseInt(data.limit, 10) : (typeof data.limit === 'number' ? data.limit : 5 * 1024 * 1024)
        };
        
        console.log('Storage query function result (normalized):', normalizedData);
        return normalizedData;
      } catch (error) {
        console.error('Error in storage query function:', error);
        // Return default data on error
        return {
          used: 0,
          limit: 5 * 1024 * 1024 // 5MB default limit
        };
      }
    },
    staleTime: 60000, // 1 minute
    refetchOnWindowFocus: true,
    refetchOnMount: true,
    retry: 3,
    retryDelay: 1000
  });

  // Debug logging
  useEffect(() => {
    console.log('Subscription data:', subscription || 'Not available');
    console.log('Storage usage data:', storageUsage || 'Not available');
    console.log('Subscription loading:', subLoading);
    console.log('Subscription error:', subError);
    console.log('Storage loading:', storageLoading);
    console.log('Storage error:', storageError);
  }, [subscription, storageUsage, subLoading, subError, storageLoading, storageError]);

  // Force refresh subscription data on mount and when subscription-updated event is fired
  useEffect(() => {
    // Function to refresh data
    const refreshData = async () => {
      console.log('Refreshing subscription and storage data...');
      try {
        // Use Promise.allSettled to handle partial failures
        const results = await Promise.allSettled([
          refetchSubscription(),
          refetchStorage()
        ]);
        
        // Check results
        if (results[0].status === 'fulfilled') {
          console.log('Fresh subscription data (raw):', results[0].value.data || 'Not available');
          
          // Force rerender with fresh data if available
          if (results[0].value.data) {
            // Normalize the subscription data
            const data = results[0].value.data;
            const normalizedData = {
              ...data,
              id: typeof data.id === 'string' ? parseInt(data.id, 10) : data.id,
              storage_limit: typeof data.storage_limit === 'string' ? 
                parseInt(data.storage_limit, 10) : 
                (typeof data.storage_limit === 'number' ? data.storage_limit : 5 * 1024 * 1024),
              price: typeof data.price === 'string' ? 
                parseFloat(data.price) : 
                (typeof data.price === 'number' ? data.price : 0)
            };
            
            console.log('Fresh subscription data (normalized):', normalizedData);
            queryClient.setQueryData(['subscription'], normalizedData);
          }
        } else {
          console.error('Failed to refresh subscription data:', results[0].reason);
        }
        
        if (results[1].status === 'fulfilled') {
          console.log('Fresh storage data (raw):', results[1].value.data || 'Not available');
          
          if (results[1].value.data) {
            // Normalize the storage data
            const data = results[1].value.data;
            const normalizedData = {
              used: typeof data.used === 'string' ? parseInt(data.used, 10) : (typeof data.used === 'number' ? data.used : 0),
              limit: typeof data.limit === 'string' ? parseInt(data.limit, 10) : (typeof data.limit === 'number' ? data.limit : 5 * 1024 * 1024)
            };
            
            console.log('Fresh storage data (normalized):', normalizedData);
            queryClient.setQueryData(['storage'], normalizedData);
          }
        } else {
          console.error('Failed to refresh storage data:', results[1].reason);
        }
      } catch (error) {
        console.error('Error refreshing data:', error);
      }
    };

    // Refresh on mount
    refreshData();
    
    // Listen for subscription updates
    eventBus.on('subscription-updated', refreshData);
    
    // Cleanup
    return () => {
      eventBus.off('subscription-updated', refreshData);
    };
  }, [refetchSubscription, refetchStorage, queryClient]);

  // Get subscription and storage display values with fallbacks
  const subscriptionName = subscription?.name || 'Free';
  const storageUsed = storageUsage?.used || 0; 
  const storageLimit = storageUsage?.limit || 5 * 1024 * 1024; // Default 5MB

  // Calculate storage usage percentage with safety check to avoid division by zero
  const storagePercentage = storageLimit > 0 ? Math.min((storageUsed / storageLimit * 100), 100) : 0;
  
  // Format storage display - handle unlimited case for Enterprise plan
  const formattedStorageLimit = subscriptionName === 'Enterprise' ? 'Unlimited' : formatStorage(storageLimit);

  // Update stats when documents or storage data changes
  useEffect(() => {
    // Update stats whenever documents or storage usage changes
    setStats(prevStats => ({
      documents: Array.isArray(documents) ? documents.length : 0,
      storage: storageUsage && typeof storageUsage.used === 'number' ? formatStorage(storageUsage.used) : '0 MB',
      shared: prevStats.shared
    }));
  }, [documents, storageUsage]);

  const features = [
    {
      title: 'Upload Documents',
      description: 'Securely upload and manage your important documents',
      icon: <Upload className="h-6 w-6 text-primary" />,
      link: '/documents',
      action: 'Upload Now'
    },
    {
      title: 'Share with QR Code',
      description: 'Generate a QR code to securely share your documents',
      icon: <QrCode className="h-6 w-6 text-primary" />,
      link: '/share',
      action: 'Create QR Code'
    },
    {
      title: 'Manage Profile',
      description: 'Update your personal details and security settings',
      icon: <User className="h-6 w-6 text-primary" />,
      link: '/profile',
      action: 'Edit Profile'
    }
  ];

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <main className="container mx-auto px-4 pt-24 pb-16">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="max-w-5xl mx-auto"
        >
          {/* Welcome Card with Subscription Info */}
          <div className="bg-gradient-to-r from-primary/90 to-tertiary/90 rounded-2xl p-8 text-white mb-8 relative overflow-hidden">
            <div className="absolute top-0 right-0 w-64 h-64 bg-white/10 rounded-full -mt-32 -mr-32" />
            <div className="absolute bottom-0 left-0 w-32 h-32 bg-white/5 rounded-full -mb-16 -ml-16" />
            <div className="relative z-10">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                <div>
                  <h1 className="text-3xl font-bold mb-2">Welcome back, {user?.fullName || 'User'}</h1>
                  <p className="text-white/80 max-w-xl">
                    Your documents are secure and ready for management. What would you like to do today?
                  </p>
                </div>
                {/* Subscription Card - clickable, navigate to subscription page */}
                <div className="w-full max-w-sm sm:w-auto">
                  <Card 
                    className="bg-white/80 backdrop-blur-md border-white/30 shadow-lg transition-all hover:shadow-xl hover:scale-105 cursor-pointer"
                    onClick={() => navigate('/subscription')}
                  >
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Crown className="h-5 w-5 text-yellow-500" />
                          <span className="font-semibold text-primary">
                            {subscriptionName} Plan
                          </span>
                        </div>
                        <ChevronRight className="h-4 w-4 text-primary/60" />
                      </div>
                      <div className="space-y-2">
                        <div className="flex justify-between text-sm text-primary">
                          <span>Storage</span>
                          <span>
                            {formatStorage(storageUsed)} / {formattedStorageLimit}
                          </span>
                        </div>
                        <Progress 
                          value={subscriptionName === 'Enterprise' ? 0 : storagePercentage} 
                          className="h-2 bg-primary/20"
                        />
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
                <div className="bg-white/10 backdrop-blur-sm rounded-xl p-4 border border-white/20">
                  <div className="text-white/70 text-sm mb-1">Documents</div>
                  <div className="text-2xl font-bold">{stats.documents}</div>
                </div>
                <div className="bg-white/10 backdrop-blur-sm rounded-xl p-4 border border-white/20">
                  <div className="text-white/70 text-sm mb-1">Storage Used</div>
                  <div className="text-2xl font-bold">{stats.storage}</div>
                </div>
                <div className="bg-white/10 backdrop-blur-sm rounded-xl p-4 border border-white/20">
                  <div className="text-white/70 text-sm mb-1">Shared</div>
                  <div className="text-2xl font-bold">{stats.shared}</div>
                </div>
              </div>
            </div>
          </div>
          
          {/* Quick Actions */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
            {features.map((feature, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                className="bg-white rounded-xl p-6 shadow-sm border border-border hover:shadow-md transition-all"
              >
                <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mb-4">
                  {feature.icon}
                </div>
                <h3 className="text-lg font-medium mb-2">{feature.title}</h3>
                <p className="text-muted-foreground mb-4">
                  {feature.description}
                </p>
                <Link to={feature.link}>
                  <Button variant="ghost" className="flex items-center gap-1 px-0 text-primary hover:text-primary hover:bg-transparent">
                    <span>{feature.action}</span>
                    <ArrowRight className="w-4 h-4" />
                  </Button>
                </Link>
              </motion.div>
            ))}
          </div>
          
          {/* Recent Activity */}
          <div className="bg-white rounded-xl p-6 shadow-sm border border-border">
            <h2 className="text-xl font-semibold mb-6">Recent Activity</h2>
            
            {documents.length > 0 ? (
              <div className="space-y-3">
                {documents.slice(0, 3).map((doc: any) => (
                  <div key={doc.id} className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center">
                        <FileText className="w-5 h-5 text-primary" />
                      </div>
                      <div>
                        <p className="font-medium">{doc.name}</p>
                        <p className="text-xs text-muted-foreground">
                          Uploaded {new Date(doc.created_at).toLocaleDateString()}
                        </p>
                      </div>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {Math.round(doc.size / 1024)} KB
                    </span>
                  </div>
                ))}
                
                {documents.length > 3 && (
                  <div className="text-center mt-4">
                    <Link to="/documents">
                      <Button variant="outline" size="sm">
                        View All Documents
                      </Button>
                    </Link>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-8">
                <p className="text-muted-foreground">No recent activity</p>
                <Button className="mt-4" asChild>
                  <Link to="/documents">Upload Your First Document</Link>
                </Button>
              </div>
            )}
          </div>
        </motion.div>
      </main>
    </div>
  );
};

export default Dashboard;
