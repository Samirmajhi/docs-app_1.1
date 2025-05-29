import { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { toast } from 'sonner';

const AuthCallback = () => {
  const [searchParams] = useSearchParams();
  const { handleGoogleCallback } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    const token = searchParams.get('token');
    const error = searchParams.get('error');
    
    if (error) {
      console.error('Google auth error:', error);
      toast.error('Authentication failed. Please try again.');
      navigate('/');
      return;
    }

    if (token) {
      handleGoogleCallback(token)
        .then(() => {
          toast.success('Successfully authenticated');
          navigate('/dashboard');
        })
        .catch((error) => {
          console.error('Error handling Google callback:', error);
          toast.error('Failed to complete authentication');
          navigate('/');
        });
    } else {
      console.error('No token received from Google');
      toast.error('Authentication failed. No token received.');
      navigate('/');
    }
  }, [searchParams, handleGoogleCallback, navigate]);

  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="text-center">
        <h1 className="text-2xl font-bold mb-4">Processing your login...</h1>
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900 mx-auto"></div>
      </div>
    </div>
  );
};

export default AuthCallback; 