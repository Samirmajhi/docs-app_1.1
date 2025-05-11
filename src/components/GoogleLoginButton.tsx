import React from 'react';
import { useAuth } from '../context/AuthContext';
import { Button, Box } from '@mui/material';
import GoogleIcon from '@mui/icons-material/Google';

const GoogleLoginButton: React.FC = () => {
  const { googleLogin } = useAuth();

  const handleGoogleLogin = async () => {
    try {
      await googleLogin();
    } catch (error) {
      console.error('Google login error:', error);
    }
  };

  return (
    <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
      <Button
        variant="contained"
        startIcon={<GoogleIcon />}
        onClick={handleGoogleLogin}
        sx={{
          backgroundColor: '#4285F4',
          '&:hover': {
            backgroundColor: '#357ABD',
          },
        }}
      >
        Sign in with Google
      </Button>
    </Box>
  );
};

export default GoogleLoginButton; 