import React, { createContext, useContext, useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import api from '@/services/api';
import { useAuth } from './AuthContext';

interface Notification {
  id: string;
  type: 'access_request' | 'access_approved' | 'access_denied';
  message: string;
  read: boolean;
  createdAt: string;
  data?: {
    requestId?: string;
    documentId?: string;
    requesterId?: string;
  };
}

interface NotificationContextType {
  notifications: Notification[];
  unreadCount: number;
  markAsRead: (id: string) => Promise<void>;
  markAllAsRead: () => Promise<void>;
}

const NotificationContext = createContext<NotificationContextType | undefined>(undefined);

export const NotificationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const { isAuthenticated } = useAuth();

  const { data, refetch } = useQuery({
    queryKey: ['notifications'],
    queryFn: async () => {
      if (!isAuthenticated) {
        return [];
      }
      const response = await api.get('/notifications');
      return response.data;
    },
    refetchInterval: 30000, // Poll every 30 seconds
    enabled: isAuthenticated, // Only fetch when authenticated
  });

  useEffect(() => {
    if (data) {
      setNotifications(data);
    }
  }, [data]);

  const unreadCount = notifications.filter(n => !n.read).length;

  const markAsRead = async (id: string) => {
    if (!isAuthenticated) return;
    
    try {
      await api.patch(`/notifications/${id}/read`);
      setNotifications(prev =>
        prev.map(n => (n.id === id ? { ...n, read: true } : n))
      );
    } catch (error) {
      toast.error('Failed to mark notification as read');
    }
  };

  const markAllAsRead = async () => {
    if (!isAuthenticated) return;
    
    try {
      await api.patch('/notifications/read-all');
      setNotifications(prev =>
        prev.map(n => ({ ...n, read: true }))
      );
    } catch (error) {
      toast.error('Failed to mark all notifications as read');
    }
  };

  return (
    <NotificationContext.Provider
      value={{
        notifications,
        unreadCount,
        markAsRead,
        markAllAsRead,
      }}
    >
      {children}
    </NotificationContext.Provider>
  );
};

export const useNotifications = () => {
  const context = useContext(NotificationContext);
  if (context === undefined) {
    throw new Error('useNotifications must be used within a NotificationProvider');
  }
  return context;
}; 