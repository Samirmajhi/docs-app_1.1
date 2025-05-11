import React, { useState } from 'react';
import { Eye, EyeOff, Mail, Phone, User, Lock } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { toast } from 'sonner';
import { motion } from 'framer-motion';
import { useAuth } from '@/context/AuthContext';

type FormMode = 'login' | 'register';

const AuthForm = () => {
  const [mode, setMode] = useState<FormMode>('login');
  const [showPassword, setShowPassword] = useState(false);
  const [formData, setFormData] = useState({
    fullName: '',
    email: '',
    mobileNumber: '',
    password: '',
    pin: ''
  });
  
  const { login, register, loading, loginWithGoogle } = useAuth();

  const toggleMode = () => {
    setMode(mode === 'login' ? 'register' : 'login');
    // Reset form data when switching modes
    setFormData({
      fullName: '',
      email: '',
      mobileNumber: '',
      password: '',
      pin: ''
    });
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.id]: e.target.value
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      if (mode === 'login') {
        await login(formData.email, formData.password);
      } else {
        if (formData.pin.length < 4 || formData.pin.length > 6) {
          return toast.error('PIN must be between 4-6 digits');
        }
        await register(
          formData.email,
          formData.password,
          formData.fullName,
          formData.mobileNumber,
          formData.pin
        );
      }
    } catch (error) {
      // Error is handled in the auth context
      console.error('Authentication error:', error);
    }
  };

  // Google login handler
  const handleGoogleLogin = async (e: React.MouseEvent) => {
    e.preventDefault();
    try {
      await loginWithGoogle();
    } catch (error) {
      console.error('Google login error:', error);
      toast.error('Failed to login with Google');
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      {/* Social Login */}
      <div className="mb-6">
        <Button 
          variant="outline" 
          className="w-full flex items-center justify-center gap-2 h-12 mb-4"
          onClick={handleGoogleLogin}
          disabled={loading}
        >
          <svg className="w-5 h-5" viewBox="0 0 24 24">
            <path
              d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              fill="#4285F4"
            />
            <path
              d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              fill="#34A853"
            />
            <path
              d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
              fill="#FBBC05"
            />
            <path
              d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
              fill="#EA4335"
            />
          </svg>
          Continue with Google
        </Button>
      </div>

      <div className="relative flex items-center py-4">
        <div className="flex-grow border-t border-muted"></div>
        <span className="flex-shrink mx-4 text-muted-foreground text-sm">or continue with email</span>
        <div className="flex-grow border-t border-muted"></div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {mode === 'register' && (
          <div className="space-y-2">
            <Label htmlFor="fullName">Full Name</Label>
            <div className="relative">
              <User className="absolute left-3 top-3 h-5 w-5 text-muted-foreground" />
              <Input
                id="fullName"
                type="text"
                placeholder="John Doe"
                className="pl-10 h-12"
                value={formData.fullName}
                onChange={handleChange}
                required
              />
            </div>
          </div>
        )}

        <div className="space-y-2">
          <Label htmlFor="email">Email</Label>
          <div className="relative">
            <Mail className="absolute left-3 top-3 h-5 w-5 text-muted-foreground" />
            <Input
              id="email"
              type="email"
              placeholder="name@example.com"
              className="pl-10 h-12"
              value={formData.email}
              onChange={handleChange}
              required
            />
          </div>
        </div>

        {mode === 'register' && (
          <div className="space-y-2">
            <Label htmlFor="mobileNumber">Mobile Number</Label>
            <div className="relative">
              <Phone className="absolute left-3 top-3 h-5 w-5 text-muted-foreground" />
              <Input
                id="mobileNumber"
                type="tel"
                placeholder="+1 (555) 123-4567"
                className="pl-10 h-12"
                value={formData.mobileNumber}
                onChange={handleChange}
                required
              />
            </div>
            <p className="text-xs text-muted-foreground">
              Enter with country code (e.g., +1, +44). You'll need this number for owner verification.
            </p>
          </div>
        )}

        <div className="space-y-2">
          <Label htmlFor="password">Password</Label>
          <div className="relative">
            <Lock className="absolute left-3 top-3 h-5 w-5 text-muted-foreground" />
            <Input
              id="password"
              type={showPassword ? "text" : "password"}
              placeholder="••••••••"
              className="pl-10 pr-10 h-12"
              value={formData.password}
              onChange={handleChange}
              required
            />
            <button
              type="button"
              className="absolute right-3 top-3 text-muted-foreground"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
            </button>
          </div>
        </div>

        {mode === 'register' && (
          <div className="space-y-2">
            <Label htmlFor="pin" className="flex items-center">
              <span>Security PIN (4-6 digits)</span>
              <span className="ml-2 text-xs bg-primary/10 text-primary px-2 py-0.5 rounded">Required for QR access</span>
            </Label>
            <Input
              id="pin"
              type="password"
              inputMode="numeric"
              pattern="[0-9]{4,6}"
              maxLength={6}
              placeholder="Enter 4-6 digit PIN"
              className="h-12"
              value={formData.pin}
              onChange={handleChange}
              required
            />
            <p className="text-xs text-muted-foreground">
              <strong>IMPORTANT:</strong> Remember this PIN! You will need it to verify yourself as the document owner when scanning QR codes.
            </p>
          </div>
        )}

        <Button 
          type="submit" 
          className="w-full h-12 mt-6"
          disabled={loading}
        >
          {loading ? (
            <div className="flex items-center">
              <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              {mode === 'login' ? 'Logging in...' : 'Creating account...'}
            </div>
          ) : (
            <>{mode === 'login' ? 'Login' : 'Create Account'}</>
          )}
        </Button>
      </form>

      <div className="mt-6 text-center">
        <p className="text-sm text-muted-foreground">
          {mode === 'login' ? "Don't have an account?" : "Already have an account?"}
          <button
            type="button"
            className="ml-1 font-medium text-primary hover:text-primary/80"
            onClick={toggleMode}
          >
            {mode === 'login' ? 'Sign up' : 'Log in'}
          </button>
        </p>
      </div>
    </motion.div>
  );
};

export default AuthForm;