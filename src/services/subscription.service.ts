import axios from 'axios';
import api from './api'; // Import the configured api client instead
import paymentService from './payment.service';

export interface SubscriptionPlan {
  id: number;
  name: string;
  storage_limit: number;
  price: number | null;
  features: string[];
}

export interface UserSubscription {
  id: number;
  user_id: string;
  plan_id: number;
  storage_used: number;
  status: string;
  start_date: string;
  end_date: string | null;
}

// Default free plan to use as fallback
const DEFAULT_FREE_PLAN: SubscriptionPlan = {
  id: 1,
  name: 'Free',
  storage_limit: 5 * 1024 * 1024, // 5MB in bytes
  price: 0,
  features: ['5MB Storage', 'Basic Document Management']
};

// Default storage usage to use as fallback
const DEFAULT_STORAGE = {
  used: 0,
  limit: 5 * 1024 * 1024 // 5MB default limit
};

class SubscriptionService {
  // Use a hardcoded URL to avoid any issues with baseUrl being undefined
  private baseUrl = 'http://34.132.75.76:7000/api';

  async getPlans(): Promise<SubscriptionPlan[]> {
    try {
      console.log('Fetching subscription plans...');
      
      // Use the configured api client instead of direct axios
      const response = await api.get('/subscription/plans');
      
      if (!response.data || !Array.isArray(response.data)) {
        console.warn('Invalid plans data received:', response.data);
        return [DEFAULT_FREE_PLAN];
      }
      
      console.log('Plans response:', response.data);
      return response.data;
    } catch (error) {
      console.error('Error fetching subscription plans:', error);
      // Return a default free plan if API call fails
      return [DEFAULT_FREE_PLAN];
    }
  }

  async getCurrentSubscription(): Promise<SubscriptionPlan> {
    try {
      console.log('Fetching current subscription...');
      
      // First try with a direct fetch to avoid any baseUrl issues
      try {
        const timestamp = new Date().getTime(); // Cache-busting parameter
        // Direct fetch call with hardcoded URL
        const response = await fetch(`http://34.132.75.76:7000/api/subscription/user?t=${timestamp}`, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token') || ''}`,
            'Content-Type': 'application/json'
          }
        });
        
        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }
        
        const data = await response.json();
        
        // Validate response data
        if (!data) {
          console.warn('Empty subscription data received');
          return DEFAULT_FREE_PLAN;
        }
        
        console.log('Current subscription response (raw):', data);
        
        // Ensure numeric values are properly converted
        const storage_limit = typeof data.storage_limit === 'string' 
          ? parseInt(data.storage_limit, 10) 
          : (typeof data.storage_limit === 'number' ? data.storage_limit : DEFAULT_FREE_PLAN.storage_limit);
        
        const price = typeof data.price === 'string'
          ? parseFloat(data.price)
          : (typeof data.price === 'number' ? data.price : 0);
        
        // Ensure all required fields are present, use defaults for any missing fields
        return {
          id: typeof data.id === 'string' ? parseInt(data.id, 10) : (data.id ?? 1),
          name: data.name ?? 'Free',
          storage_limit: storage_limit,
          price: price,
          features: data.features ?? DEFAULT_FREE_PLAN.features
        };
      } catch (fetchError) {
        console.error('Error with direct fetch, trying api client:', fetchError);
        
        // If direct fetch fails, try with api client
        const response = await api.get(`/subscription/user?t=${new Date().getTime()}`);
        
        if (!response.data) {
          console.warn('Empty subscription data received');
          return DEFAULT_FREE_PLAN;
        }
        
        const data = response.data;
        console.log('Current subscription response (raw from api client):', data);
        
        // Ensure numeric values are properly converted
        const storage_limit = typeof data.storage_limit === 'string' 
          ? parseInt(data.storage_limit, 10) 
          : (typeof data.storage_limit === 'number' ? data.storage_limit : DEFAULT_FREE_PLAN.storage_limit);
        
        const price = typeof data.price === 'string'
          ? parseFloat(data.price)
          : (typeof data.price === 'number' ? data.price : 0);
        
        return {
          id: typeof data.id === 'string' ? parseInt(data.id, 10) : (data.id ?? 1),
          name: data.name ?? 'Free',
          storage_limit: storage_limit,
          price: price,
          features: data.features ?? DEFAULT_FREE_PLAN.features
        };
      }
    } catch (error) {
      console.error('Error fetching current subscription:', error);
      return DEFAULT_FREE_PLAN;
    }
  }

  async getStorageUsage(): Promise<{ used: number; limit: number }> {
    try {
      console.log('Fetching storage usage...');
      
      // First try with a direct fetch to avoid any baseUrl issues
      try {
        const timestamp = new Date().getTime(); // Cache-busting parameter
        // Direct fetch call with hardcoded URL
        const response = await fetch(`http://34.132.75.76:7000/api/subscription/storage?t=${timestamp}`, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token') || ''}`,
            'Content-Type': 'application/json'
          }
        });
        
        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (!data) {
          console.warn('Empty storage data received');
          return DEFAULT_STORAGE;
        }
        
        console.log('Storage usage response (raw):', data);
        
        // Ensure values are numbers, converting from strings if necessary
        return {
          used: typeof data.used === 'string' ? parseInt(data.used, 10) : (typeof data.used === 'number' ? data.used : 0),
          limit: typeof data.limit === 'string' ? parseInt(data.limit, 10) : (typeof data.limit === 'number' ? data.limit : DEFAULT_STORAGE.limit)
        };
      } catch (fetchError) {
        console.error('Error with direct fetch, trying api client:', fetchError);
        
        // If direct fetch fails, try with api client
        const response = await api.get(`/subscription/storage?t=${new Date().getTime()}`);
        
        if (!response.data) {
          console.warn('Empty storage data received');
          return DEFAULT_STORAGE;
        }
        
        const data = response.data;
        console.log('Storage usage response (raw from api):', data);
        
        // Ensure values are numbers, converting from strings if necessary
        return {
          used: typeof data.used === 'string' ? parseInt(data.used, 10) : (typeof data.used === 'number' ? data.used : 0),
          limit: typeof data.limit === 'string' ? parseInt(data.limit, 10) : (typeof data.limit === 'number' ? data.limit : DEFAULT_STORAGE.limit)
        };
      }
    } catch (error) {
      console.error('Error fetching storage usage:', error);
      return DEFAULT_STORAGE;
    }
  }

  async updateSubscription(planId: number): Promise<void> {
    try {
      console.log('Updating subscription to plan ID:', planId);
      
      if (!planId || planId <= 0) {
        throw new Error('Invalid plan ID');
      }
      
      const response = await api.post('/subscription/update', { planId });
      console.log('Update subscription response:', response.data);
    } catch (error) {
      console.error('Error updating subscription:', error);
      throw error;
    }
  }

  // New method to handle payment for subscription plans
  async handlePlanPayment(plan: SubscriptionPlan): Promise<void> {
    if (!plan || plan.id <= 0) {
      throw new Error('Invalid plan');
    }

    // If it's a free plan, just update subscription directly
    if (plan.price === 0) {
      await this.updateSubscription(plan.id);
      return;
    }

    // For paid plans, initialize eSewa payment
    try {
      const planId = typeof plan.id === 'string' ? parseInt(plan.id, 10) : plan.id;
      const paymentPrice = typeof plan.price === 'number' ? plan.price : 0;
      
      console.log('Initializing payment with plan ID:', planId, 'and price:', paymentPrice);
      
      const response = await paymentService.initializeEsewaPayment(planId, paymentPrice);
      
      if (!response.success) {
        throw new Error(response.message || response.error || 'Failed to initialize payment');
      }
      
      // Submit the form to eSewa
      paymentService.submitEsewaForm({
        amount: paymentPrice,
        transaction_uuid: response.purchasedItemData._id,
        signature: response.payment.signature
      });
      
    } catch (error) {
      console.error('Error initializing payment:', error);
      throw error;
    }
  }

  // Method to handle payment verification
  async verifyPayment(data: string): Promise<any> {
    try {
      const response = await paymentService.verifyEsewaPayment(data);
      
      // Return the complete response object from the API
      console.log('Payment verification response:', response);
      return response;
    } catch (error: any) {
      console.error('Error verifying payment:', error);
      // Return an error object for consistent handling in the UI
      return {
        success: false,
        message: error?.message || 'Error verifying payment',
        error: error
      };
    }
  }
}

export default new SubscriptionService(); 