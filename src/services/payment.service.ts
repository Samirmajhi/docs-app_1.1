import api from './api';

export interface PaymentInitializeResponse {
  success: boolean;
  payment: {
    signature: string;
    signed_field_names: string;
  };
  purchasedItemData: {
    _id: string;
    totalPrice: number;
  };
  message?: string;
  error?: string;
}

export interface PaymentVerificationResponse {
  success: boolean;
  message: string;
  paymentData?: any;
  error?: string;
}

class PaymentService {
  async initializeEsewaPayment(planId: number, price: number): Promise<PaymentInitializeResponse> {
    try {
      console.log('Initializing eSewa payment for plan:', planId, 'with price:', price);
      
      // Validate parameters
      if (planId === undefined || planId === null || isNaN(planId)) {
        throw new Error('Invalid plan ID');
      }
      
      if (price === undefined || price === null || isNaN(price)) {
        throw new Error('Invalid price');
      }
      
      // Ensure parameters are correctly typed
      const requestData = {
        planId: Number(planId),
        totalPrice: Number(price)
      };
      
      console.log('Payment request data:', requestData);
      
      const response = await api.post('/payments/initialize-esewa', requestData);
      console.log('Payment initialization response:', response.data);
      return response.data;
    } catch (error: any) {
      console.error('Error initializing eSewa payment:', error);
      console.error('Error details:', error.response?.data);
      throw new Error(error.response?.data?.message || error.message || 'Failed to initialize payment');
    }
  }

  async verifyEsewaPayment(data: string): Promise<PaymentVerificationResponse> {
    try {
      console.log('Verifying eSewa payment with data:', data.substring(0, 20) + '...');
      
      // Don't double-encode the data parameter - it's already URL encoded
      // Just pass it directly to the API endpoint
      const encodedData = encodeURIComponent(data);
      console.log('Encoded data for verification:', encodedData.substring(0, 30) + '...');
      
      const response = await api.get(`/payments/complete-payment?data=${encodedData}`);
      console.log('Payment verification response:', response.data);
      return response.data;
    } catch (error: any) {
      console.error('Error verifying eSewa payment:', error);
      console.error('Error details:', error.response?.data);
      throw new Error(error.response?.data?.message || 'Failed to verify payment');
    }
  }

  // Helper method to handle form submission to eSewa
  submitEsewaForm(formData: {
    amount: number;
    transaction_uuid: string;
    signature: string;
  }): void {
    // Create a dynamic form element
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = 'https://rc-epay.esewa.com.np/api/epay/main/v2/form';
    form.style.display = 'none';

    console.log('Submitting eSewa form with data:', formData);

    // Add required form fields
    const fields = {
      amount: formData.amount.toString(),
      tax_amount: '0',
      total_amount: formData.amount.toString(),
      transaction_uuid: formData.transaction_uuid,
      product_code: 'EPAYTEST',
      product_service_charge: '0',
      product_delivery_charge: '0',
      success_url: `${window.location.origin}/subscription/payment-success`,
      failure_url: `${window.location.origin}/subscription/payment-failure`,
      signed_field_names: 'total_amount,transaction_uuid,product_code',
      signature: formData.signature
    };

    console.log('Form fields:', fields);

    // Create and append input elements
    for (const [key, value] of Object.entries(fields)) {
      const input = document.createElement('input');
      input.type = 'hidden';
      input.name = key;
      input.value = value;
      form.appendChild(input);
    }

    // Append form to body, submit it, and remove it
    document.body.appendChild(form);
    console.log('Submitting eSewa payment form...');
    form.submit();
    document.body.removeChild(form);
  }
}

export default new PaymentService(); 