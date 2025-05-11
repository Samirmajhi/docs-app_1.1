import React, { useState, useEffect } from 'react';
import Navbar from '@/components/layout/Navbar';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { toast } from 'sonner';
import { motion } from 'framer-motion';
import { Shield, User, Phone, Mail, Key } from 'lucide-react';
import { useAuth } from '@/context/AuthContext';

const Profile = () => {
  const { user, updateUserProfile } = useAuth();
  const [isEditing, setIsEditing] = useState(false);
  const [formData, setFormData] = useState({
    fullName: '',
    email: '',
    mobileNumber: '',
    pin: ''
  });
  const [showPin, setShowPin] = useState(false);

  useEffect(() => {
    if (user) {
      // Log current user data for debugging
      console.log('Loading user profile data:', {
        ...user,
        pin: user.pin ? '✓ Present' : '✗ Missing'
      });
      
      setFormData({
        fullName: user.fullName || '',
        email: user.email || '',
        mobileNumber: user.mobileNumber || '',
        pin: user.pin || ''
      });
    }
  }, [user]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      // Always include PIN in update if it's been changed
      const updateData = {
        fullName: formData.fullName,
        mobileNumber: formData.mobileNumber,
        pin: formData.pin // Always send PIN to ensure it's updated
      };
      
      console.log('Updating profile with data:', {
        ...updateData,
        pin: updateData.pin ? '✓ Present' : '✗ Missing'
      });
      
      await updateUserProfile(updateData);
      
      setIsEditing(false);
      toast.success('Profile updated successfully');
    } catch (error) {
      console.error('Error updating profile:', error);
      toast.error('Failed to update profile');
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <main className="container mx-auto px-4 pt-24 pb-16">
        <div className="max-w-3xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-white rounded-xl border border-border shadow-sm p-8"
          >
            <div className="flex flex-col md:flex-row items-center md:items-start gap-8">
              <div className="text-center">
                <Avatar className="h-24 w-24 border-2 border-primary">
                  <AvatarImage src={`https://api.dicebear.com/7.x/lorelei/svg?seed=${formData.fullName}`} alt="Profile" />
                  <AvatarFallback>{formData.fullName?.split(' ').map(n => n[0]).join('') || 'U'}</AvatarFallback>
                </Avatar>
                {!isEditing && (
                  <Button 
                    variant="outline" 
                    size="sm" 
                    className="mt-4"
                    onClick={() => setIsEditing(true)}
                  >
                    Edit Profile
                  </Button>
                )}
              </div>
              
              <div className="flex-1">
                {isEditing ? (
                  <form onSubmit={handleSave} className="space-y-4">
                    <h2 className="text-2xl font-bold mb-6">Edit Profile</h2>
                    
                    <div className="space-y-2">
                      <Label htmlFor="fullName">Full Name</Label>
                      <div className="relative">
                        <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                        <Input
                          id="fullName"
                          name="fullName"
                          value={formData.fullName}
                          onChange={handleChange}
                          className="pl-10"
                        />
                      </div>
                    </div>
                    
                    <div className="space-y-2">
                      <Label htmlFor="email">Email</Label>
                      <div className="relative">
                        <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                        <Input
                          id="email"
                          name="email"
                          type="email"
                          value={formData.email}
                          onChange={handleChange}
                          className="pl-10"
                          disabled
                        />
                      </div>
                      <p className="text-xs text-muted-foreground">Email cannot be changed</p>
                    </div>
                    
                    <div className="space-y-2">
                      <Label htmlFor="mobileNumber">Mobile Number</Label>
                      <div className="relative">
                        <Phone className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                        <Input
                          id="mobileNumber"
                          name="mobileNumber"
                          value={formData.mobileNumber}
                          onChange={handleChange}
                          className="pl-10"
                          placeholder="e.g. +1234567890"
                        />
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Required for owner verification when accessing documents
                      </p>
                    </div>
                    
                    <div className="space-y-2">
                      <Label htmlFor="pin">Security PIN</Label>
                      <div className="relative">
                        <Key className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                        <Input
                          id="pin"
                          name="pin"
                          type="text"
                          inputMode="numeric"
                          value={formData.pin}
                          onChange={handleChange}
                          className="pl-10"
                          maxLength={6}
                          pattern="[0-9]{4,6}"
                          placeholder={formData.pin ? '••••••' : 'Enter 4-6 digit PIN'}
                        />
                      </div>
                      <p className="text-xs text-muted-foreground">
                        {formData.pin ? 'Leave empty to keep current PIN' : '4-6 digit PIN used for owner authentication'}
                      </p>
                    </div>
                    
                    <div className="flex gap-3 pt-2">
                      <Button type="submit">Save Changes</Button>
                      <Button type="button" variant="ghost" onClick={() => setIsEditing(false)}>
                        Cancel
                      </Button>
                    </div>
                  </form>
                ) : (
                  <div>
                    <h2 className="text-2xl font-bold mb-6">Profile Information</h2>
                    
                    <div className="space-y-4">
                      <div className="flex flex-col space-y-1">
                        <span className="text-sm text-muted-foreground">Full Name</span>
                        <span className="font-medium">{formData.fullName || 'Not set'}</span>
                      </div>
                      
                      <div className="flex flex-col space-y-1">
                        <span className="text-sm text-muted-foreground">Email</span>
                        <span className="font-medium">{formData.email}</span>
                      </div>
                      
                      <div className="flex flex-col space-y-1">
                        <span className="text-sm text-muted-foreground">Mobile Number</span>
                        <span className="font-medium">{formData.mobileNumber || 'Not set - Required for verification'}</span>
                      </div>
                      
                      <div className="flex flex-col space-y-1">
                        <span className="text-sm text-muted-foreground">Security PIN</span>
                        <div className="flex items-center gap-2">
                          <span className="font-medium">
                            {formData.pin ? (showPin ? formData.pin : '••••••') : 'Not set - Required for verification'}
                          </span>
                          {formData.pin && (
                            <div className="flex items-center gap-2">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => setShowPin(!showPin)}
                                className="h-6 px-2"
                              >
                                {showPin ? 'Hide' : 'Show'}
                              </Button>
                              <Shield className="h-4 w-4 text-green-500" />
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
            
            <div className="mt-8 pt-6 border-t border-gray-200">
              <div className="flex items-center gap-3 text-muted-foreground">
                <Shield className="h-5 w-5 text-primary" />
                <span>Your account is secured with end-to-end encryption</span>
              </div>
            </div>
          </motion.div>
        </div>
      </main>
    </div>
  );
};

export default Profile;