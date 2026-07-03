import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Layout } from './components/Layout';

// Auth Pages
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { ForgotPassword } from './pages/ForgotPassword';

// Feature Pages
import { Dashboard } from './pages/Dashboard';
import { History } from './pages/History';
import { IpScanner } from './pages/features/IpScanner';
import { UrlScanner } from './pages/features/UrlScanner';
import { FileIntegrity } from './pages/features/FileIntegrity';
import { MetadataViewer } from './pages/features/MetadataViewer';
import { EmailHeaderAnalyzer } from './pages/features/EmailHeaderAnalyzer';
import { SecurityHeadersChecker } from './pages/features/SecurityHeadersChecker';
import { PhishingDetector } from './pages/features/PhishingDetector';
import { PasswordStrength } from './pages/features/PasswordStrength';
import { CodeScanner } from './pages/features/CodeScanner';
import { RansomwareDetect } from './pages/features/RansomwareDetect';
import { BrowserExtensionScanner } from './pages/features/BrowserExtensionScanner';
import { AiAssistant } from './pages/features/AiAssistant';
import { ReportsExporter } from './pages/features/ReportsExporter';
import { WhoisDnsLookup } from './pages/features/WhoisDnsLookup';
import { SslChecker } from './pages/features/SslChecker';
import { ChangePassword } from './pages/ChangePassword';
import { Profile } from './pages/Profile';
import AdminPanel from './pages/AdminPanel';
import AdminLogin from './pages/AdminLogin';

// Protected Route Wrapper
const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const { isAuthenticated, isLoading } = useAuth();
  
  if (isLoading) return <div className="loading-screen">INITIALIZING SECURITY PROTOCOLS...</div>;
  
  return isAuthenticated ? children : <Navigate to="/login" />;
};

function AppRoutes() {
  return (
    <Routes>
      {/* Public Routes */}
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />

      {/* Standalone Admin routes — use their own admin_token, not the regular user token */}
      <Route path="/admin-login" element={<AdminLogin />} />
      <Route path="/admin" element={<AdminPanel />} />

      {/* Protected Routes */}
      <Route path="/" element={
        <ProtectedRoute>
          <Layout />
        </ProtectedRoute>
      }>
        <Route index element={<Dashboard />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="history" element={<History />} />
        
        {/* Features */}
        <Route path="ip" element={<IpScanner />} />
        <Route path="url" element={<UrlScanner />} />
        
        <Route path="files/integrity" element={<FileIntegrity />} />
        <Route path="files/metadata" element={<MetadataViewer />} />
        
        <Route path="scan/email-headers" element={<EmailHeaderAnalyzer />} />
        <Route path="scan/security-headers" element={<SecurityHeadersChecker />} />
        <Route path="scan/phishing" element={<PhishingDetector />} />
        <Route path="scan/password" element={<PasswordStrength />} />
        <Route path="scan/code" element={<CodeScanner />} />
        <Route path="scan/ransomware" element={<RansomwareDetect />} />
        <Route path="scan/extensions" element={<BrowserExtensionScanner />} />
        <Route path="whois-dns" element={<WhoisDnsLookup />} />
        <Route path="scan/ssl" element={<SslChecker />} />
        
        <Route path="ai" element={<AiAssistant />} />
        <Route path="reports" element={<ReportsExporter />} />
        <Route path="change-password" element={<ChangePassword />} />
        <Route path="profile" element={<Profile />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

function App() {
  return (
    <AuthProvider>
      <BrowserRouter basename={import.meta.env.BASE_URL}>
        <AppRoutes />
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
