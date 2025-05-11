import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "./context/AuthContext";
import { NotificationProvider } from "./context/NotificationContext";
import ProtectedRoute from "./components/auth/ProtectedRoute";
import Index from "./pages/Index";
import Dashboard from "./pages/Dashboard";
import Documents from "./pages/Documents";
import Share from "./pages/Share";
import Access from "./pages/Access";
import Profile from "./pages/Profile";
import NotFound from "./pages/NotFound";
import AccessRequestDetails from './pages/AccessRequestDetails';
import AccessRequestResponse from "./pages/AccessRequestResponse";
import ApprovedDocuments from "./pages/ApprovedDocuments";
import AuthCallback from "./pages/AuthCallback";
import AuthError from "./pages/AuthError";
import Subscription from "./pages/Subscription";
import Analytics from "./pages/Analytics";
import PaymentSuccess from "./pages/PaymentSuccess";
import PaymentFailure from "./pages/PaymentFailure";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <AuthProvider>
          <NotificationProvider>
          <Routes>
            <Route path="/" element={<Index />} />
            <Route path="/auth/callback" element={<AuthCallback />} />
            <Route path="/auth/error" element={<AuthError />} />
            <Route path="/dashboard" element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            } />
            <Route path="/documents" element={
              <ProtectedRoute>
                <Documents />
              </ProtectedRoute>
            } />
            <Route path="/share" element={
              <ProtectedRoute>
                <Share />
              </ProtectedRoute>
            } />
            <Route path="/access" element={<Access />} />
            <Route path="/profile" element={
              <ProtectedRoute>
                <Profile />
              </ProtectedRoute>
            } />
            <Route path="/access-requests/:requestId/:action" element={
              <ProtectedRoute>
                <AccessRequestResponse />
              </ProtectedRoute>
            } />
            <Route path="/access-requests/:requestId" element={
              <ProtectedRoute>
                <AccessRequestDetails />
              </ProtectedRoute>
            } />
            <Route path="/approved-documents/:requestId" element={<ApprovedDocuments />} />
            <Route path="/access-request/:requestId" element={<AccessRequestDetails />} />
            <Route path="/subscription" element={
              <ProtectedRoute>
                <Subscription />
              </ProtectedRoute>
            } />
            <Route path="/subscription/payment-success" element={
              <ProtectedRoute>
                <PaymentSuccess />
              </ProtectedRoute>
            } />
            <Route path="/subscription/payment-failure" element={
              <ProtectedRoute>
                <PaymentFailure />
              </ProtectedRoute>
            } />
            <Route path="/analytics" element={
              <ProtectedRoute>
                <Analytics />
              </ProtectedRoute>
            } />
            {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
            <Route path="*" element={<NotFound />} />
          </Routes>
          </NotificationProvider>
        </AuthProvider>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
