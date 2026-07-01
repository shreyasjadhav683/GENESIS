import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Card } from '../components/Card';
import { Input } from '../components/Input';
import { Button } from '../components/Button';
import { api } from '../services/api';
import { User, Lock, Cpu } from 'lucide-react';
import { ThemeToggle } from '../components/ThemeToggle';

export const ForgotPassword: React.FC = () => {
  const [step, setStep] = useState(1); // 1: Identify, 2: Verify OTP, 3: Success
  const [identifier, setIdentifier] = useState('');
  const [email, setEmail] = useState('');
  
  // Verification Inputs
  const [otp, setOtp] = useState('');
  
  const [newPassword, setNewPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [otpCooldown, setOtpCooldown] = useState(0);

  useEffect(() => {
    let interval: any;
    if (otpCooldown > 0) {
      interval = setInterval(() => {
        setOtpCooldown((prev) => prev - 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [otpCooldown]);
  
  const navigate = useNavigate();

  const handleIdentify = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
        const res = await api.post('/auth/identify', { identifier });
        setEmail(res.data.email);
        
        // Automatically send OTP
        await handleSendOtp(res.data.email);
    } catch (err: any) {
        setError('User not found');
        setLoading(false);
    }
  };

  const handleSendOtp = async (userEmail: string) => {
      setLoading(true); // Ensure loading stays true if called from identify
      setError('');
      try {
          await api.post('/auth/request-otp', { email: userEmail, purpose: 'reset' });
          setStep(2); // Go directly to Verify
          setOtpCooldown(60);
      } catch (err: any) {
          setError('Failed to send OTP. Please try again.');
      } finally {
          setLoading(false);
      }
  };
  
  const handleReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
        await api.post('/auth/recover-with-otp', {
            email,
            otp,
            new_password: newPassword
        });
        setStep(3);
        setTimeout(() => navigate('/login'), 3000);
    } catch (err: any) {
        setError(err.response?.data?.detail || 'Verification failed');
    } finally {
        setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-bg-blob"></div>
      <div style={{ position: 'absolute', top: '1rem', right: '1rem', zIndex: 50 }}>
        <ThemeToggle />
      </div>
      <div className="login-content">
        <div className="login-header">
            <div style={{ 
                display: 'inline-flex', alignItems: 'center', justifyContent: 'center', 
                padding: '1.5rem', borderRadius: '50%', 
                border: '2px solid hsl(var(--color-primary))',
                backgroundColor: 'hsla(var(--bg-card), 0.3)',
                backdropFilter: 'blur(4px)',
                marginBottom: '1rem',
                boxShadow: 'var(--card-glow)'
            }}>
                <Cpu size={48} color="hsl(var(--color-primary))" className="animate-pulse-glow" />
            </div>
            <h1 className="login-title">RECOVERY</h1>
            <p style={{ color: 'hsl(var(--color-primary))', letterSpacing: '0.3em', fontSize: '0.75rem', fontWeight: 'bold', textTransform: 'uppercase', opacity: 0.8 }}>
                Account Access Restoration
            </p>
        </div>

        <Card className="login-card">
            {step === 1 && (
                <form onSubmit={handleIdentify} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    <p style={{ textAlign: 'center', color: 'hsl(var(--text-secondary))' }}>
                        Enter username or email to locate account.
                    </p>
                    <Input
                        icon={<User size={18} />}
                        placeholder="Username or Email"
                        value={identifier}
                        onChange={(e) => setIdentifier(e.target.value)}
                        required
                    />
                    {error && <div style={{ color: '#ef4444', textAlign: 'center' }}>{error}</div>}
                    <Button type="submit" variant="primary" className="w-full" disabled={loading}>
                        {loading ? 'SEARCHING...' : 'FIND ACCOUNT'}
                    </Button>
                </form>
            )}

            {step === 2 && (
                <form onSubmit={handleReset} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    <div style={{ padding: '1rem', background: 'hsla(var(--color-primary), 0.1)', borderRadius: '0.5rem', border: '1px solid hsl(var(--color-primary))' }}>
                        <p style={{ margin: 0, fontWeight: 'bold', fontSize: '0.875rem', color: 'hsl(var(--color-primary))' }}>
                            EMAIL OTP SENT
                        </p>
                        <p style={{ margin: '0.5rem 0 0 0' }}>
                           Check your email for the code.
                        </p>
                    </div>
                    
                    <div className="flex flex-col gap-2">
                            <Input
                            icon={<Lock size={18} />}
                            placeholder="Enter 6-digit Code"
                            value={otp}
                            onChange={(e) => setOtp(e.target.value)}
                            required
                        />
                        <div className="text-right">
                            <button 
                                type="button"
                                onClick={() => handleSendOtp(email)}
                                disabled={otpCooldown > 0 || loading}
                                style={{ 
                                    background: 'none', 
                                    border: 'none', 
                                    color: otpCooldown > 0 ? 'hsl(var(--text-secondary))' : 'hsl(var(--color-primary))',
                                    cursor: otpCooldown > 0 ? 'not-allowed' : 'pointer',
                                    fontSize: '0.875rem',
                                    textDecoration: 'underline'
                                }}
                            >
                                {otpCooldown > 0 ? `Resend OTP in ${otpCooldown}s` : 'Resend OTP'}
                            </button>
                        </div>
                    </div>
                    
                        <Input
                        icon={<Lock size={18} />}
                        placeholder="New Password"
                        type="password"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        required
                    />
                    
                    {error && <div style={{ color: '#ef4444', textAlign: 'center' }}>{error}</div>}
                    <Button type="submit" variant="primary" className="w-full" disabled={loading}>
                        {loading ? 'RESETTING...' : 'RESET PASSWORD'}
                    </Button>
                        <button type="button" onClick={() => setStep(1)} style={{ background: 'none', border: 'none', color: 'hsl(var(--text-secondary))', cursor: 'pointer', width: '100%' }}>
                        Back to Search
                    </button>
                </form>
            )}

            {step === 3 && (
                <div style={{ textAlign: 'center' }}>
                    <h3 style={{ color: 'hsl(var(--color-primary))' }}>SUCCESS</h3>
                    <p>Password has been reset.</p>
                    <p>Redirecting to login...</p>
                </div>
            )}

            <div style={{ textAlign: 'center', marginTop: '1.5rem' }}>
                <Link to="/login" style={{ color: 'hsl(var(--text-secondary))', textDecoration: 'none', fontSize: '0.875rem' }}>
                    Back to Login
                </Link>
            </div>
        </Card>
      </div>
    </div>
  );
};
