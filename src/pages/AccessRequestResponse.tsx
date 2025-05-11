import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Loader2, CheckCircle, XCircle } from 'lucide-react';
import { toast } from 'sonner';
import api from '@/services/api';
import { useAuth } from '@/context/AuthContext';

const AccessRequestResponse = () => {
  const { requestId, action } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const handleRequest = async () => {
      try {
        setLoading(true);
        if (!user) {
          setError('Please log in to process this request');
          return;
        }

        // First verify the request exists and user has access
        const verifyResponse = await api.get(`/access/requests/${requestId}`);
        if (verifyResponse.data.ownerId !== user.id) {
          setError('You are not authorized to process this request');
          return;
        }

        const response = await api.post(`/access/requests/${requestId}/${action}`);
        
        if (response.data.success) {
          toast.success(
            action === 'approve' 
              ? 'Access request approved successfully' 
              : action === 'deny'
              ? 'Access request denied successfully'
              : 'Access request modified successfully'
          );
          
          // Redirect to dashboard after 2 seconds
          setTimeout(() => {
            navigate('/dashboard');
          }, 2000);
        } else {
          setError(response.data.message || 'Failed to process request');
        }
      } catch (err: any) {
        if (err.response?.status === 401) {
          setError('Please log in to process this request');
        } else if (err.response?.status === 403) {
          setError('You are not authorized to process this request');
        } else if (err.response?.status === 404) {
          setError('Access request not found');
        } else {
          setError(err.response?.data?.message || 'An error occurred while processing your request');
        }
      } finally {
        setLoading(false);
      }
    };

    handleRequest();
  }, [requestId, action, navigate, user]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="w-8 h-8 animate-spin mx-auto mb-4 text-primary" />
          <p className="text-muted-foreground">Processing your request...</p>
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
              <XCircle className="w-6 h-6" />
              Error
            </CardTitle>
            <CardDescription>{error}</CardDescription>
          </CardHeader>
          <CardContent>
            {error === 'Please log in to process this request' ? (
              <Button 
                onClick={() => navigate('/login')}
                className="w-full"
              >
                Log In
              </Button>
            ) : (
              <Button 
                onClick={() => navigate('/dashboard')}
                className="w-full"
              >
                Return to Dashboard
              </Button>
            )}
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-green-500">
            <CheckCircle className="w-6 h-6" />
            Success
          </CardTitle>
          <CardDescription>
            {action === 'approve' 
              ? 'Access request has been approved' 
              : action === 'deny'
              ? 'Access request has been denied'
              : 'Access request has been modified'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground mb-4">
            You will be redirected to the dashboard shortly...
          </p>
          <Button 
            onClick={() => navigate('/dashboard')}
            className="w-full"
          >
            Return to Dashboard Now
          </Button>
        </CardContent>
      </Card>
    </div>
  );
};

export default AccessRequestResponse; 