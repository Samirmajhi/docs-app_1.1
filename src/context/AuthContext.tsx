import React, { createContext, useState, useEffect, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import authService, { User } from '@/services/auth.service';
import { toast } from 'sonner';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, fullName: string, mobileNumber: string, pin: string) => Promise<void>;
  logout: () => void;
  updateUserProfile: (data: Partial<User>) => Promise<void>;
  googleLogin: () => Promise<void>;
  handleGoogleCallback: (token: string) => Promise<void>;
  loginWithGoogle: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  // Check if user is already logged in
  useEffect(() => {
    const checkAuthStatus = async () => {
      const token = localStorage.getItem('token');
      const savedUser = localStorage.getItem('user');
      
      if (token && savedUser) {
        try {
          // Parse saved user and include the pin field from storage
          const parsedUser = JSON.parse(savedUser);
          
          // Verify token by fetching profile
          const userProfile = await authService.getProfile();
          
          // Log details about the PIN for debugging
          console.log('User profile from API:', userProfile);
          console.log('PIN from API:', userProfile.pin);
          console.log('PIN from local storage:', parsedUser.pin);
          
          // Always use the PIN from localStorage if it exists there
          const finalPin = parsedUser.pin || userProfile.pin || '';
          
          const finalUser = {
            ...userProfile,
            pin: finalPin
          };
          
          setUser(finalUser);
          
          // Update localStorage with merged data (ensure PIN is preserved)
          localStorage.setItem('user', JSON.stringify(finalUser));
          
          console.log('Final user object after auth check:', {
            ...finalUser,
            pin: finalPin ? '✓ Present' : '✗ Missing'
          });
        } catch (error) {
          console.error('Failed to validate token:', error);
          localStorage.removeItem('token');
          localStorage.removeItem('user');
          setUser(null);
        }
      }
      
      setLoading(false);
    };
    
    checkAuthStatus();
  }, []);

  const login = async (email: string, password: string) => {
    try {
      setLoading(true);
      const response = await authService.login({ email, password });
      
      // Ensure pin is included in the stored user data
      const userData = {
        ...response.user,
        pin: response.user.pin || ''
      };
      
      localStorage.setItem('token', response.token);
      localStorage.setItem('user', JSON.stringify(userData));
      console.log('User data after login:', userData);
      console.log('PIN saved after login:', userData.pin ? '✓ Present' : '✗ Missing');
      
      setUser(userData);
      navigate('/dashboard');
      toast.success('Login successful');
    } catch (error: any) {
      toast.error(error.response?.data?.message || 'Login failed');
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const register = async (email: string, password: string, fullName: string, mobileNumber: string, pin: string) => {
    try {
      setLoading(true);
      const response = await authService.register({ email, password, fullName, mobileNumber, pin });
      
      // Log registration data for debugging
      console.log('Registration data sent:', { email, fullName, mobileNumber, pin: pin ? '✓ Present' : '✗ Missing' });
      
      // Ensure the pin is included in the user object for local storage
      const userData = {
        ...response.user,
        pin: pin || ''
      };
      
      localStorage.setItem('token', response.token);
      localStorage.setItem('user', JSON.stringify(userData));
      console.log('User data after registration:', userData);
      console.log('PIN saved after registration:', userData.pin ? '✓ Present' : '✗ Missing');
      
      setUser(userData);
      navigate('/dashboard');
      toast.success('Registration successful');
    } catch (error: any) {
      toast.error(error.response?.data?.message || 'Registration failed');
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    navigate('/');
    toast.success('Logged out successfully');
  };

  const updateUserProfile = async (data: Partial<User>) => {
    try {
      setLoading(true);
      const response = await authService.updateProfile(data);
      
      // Get current user data from localStorage to preserve any fields
      const currentUserData = localStorage.getItem('user');
      let parsedCurrentUser = {};
      
      if (currentUserData) {
        try {
          parsedCurrentUser = JSON.parse(currentUserData);
        } catch (e) {
          console.error('Error parsing current user data:', e);
        }
      }
      
      // Ensure we preserve the PIN field during update
      const updatedUser = {
        ...parsedCurrentUser,
        ...response.user,
        pin: data.pin || response.user.pin || (parsedCurrentUser as any).pin || ''
      };
      
      // Update localStorage and state
      localStorage.setItem('user', JSON.stringify(updatedUser));
      setUser(updatedUser as User);
      
      console.log('Updated user data:', {
        ...updatedUser,
        pin: updatedUser.pin ? '✓ Present' : '✗ Missing'
      });
      
      toast.success('Profile updated successfully');
    } catch (error: any) {
      toast.error(error.response?.data?.message || 'Failed to update profile');
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const googleLogin = async () => {
    try {
      setLoading(true);
      await authService.googleLogin();
    } catch (error: any) {
      toast.error(error.message || 'Failed to initiate Google login');
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleCallback = async (token: string) => {
    try {
      setLoading(true);
      const response = await authService.handleGoogleCallback(token);
      setUser(response.user);
      navigate('/dashboard');
      toast.success('Google login successful');
    } catch (error: any) {
      toast.error(error.message || 'Failed to complete Google login');
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const loginWithGoogle = async () => {
    try {
      setLoading(true);
      await googleLogin();
    } catch (error: any) {
      toast.error(error.message || 'Failed to login with Google');
      throw error;
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        isAuthenticated: !!user,
        login,
        register,
        logout,
        updateUserProfile,
        googleLogin,
        handleGoogleCallback,
        loginWithGoogle
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};