export interface SubscriptionPlan {
    id: number;
    name: string;
    storage_limit: number;
    price: number | null;
    features: string[];
}

export interface UserSubscription {
    plan: SubscriptionPlan;
    startDate: Date;
    endDate: Date | null;
    status: 'active' | 'expired' | 'cancelled';
    autoRenew: boolean;
}

export interface StorageUsage {
    used: number;
    limit: number;
    percentage: number;
} 