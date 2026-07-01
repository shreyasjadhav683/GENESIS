import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card } from '../components/Card';
import { Input } from '../components/Input';
import { Button } from '../components/Button';
import { useAuth } from '../context/AuthContext';
import { Lock, Mail, ShieldAlert, Eye, EyeOff } from 'lucide-react';
import { api } from '../services/api';

export const ChangePassword = () => {
    const { user } = useAuth();
    const navigate = useNavigate();
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [otp, setOtp] = useState('');
    
    // Step 1: Request OTP
    // Step 2: Enter & Verify OTP
    // Step 3: Set New Password
    const [step, setStep] = useState(1); 
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [otpCooldown, setOtpCooldown] = useState(0);
    const [showPassword, setShowPassword] = useState(false);

    useEffect(() => {
        let interval: any;
        if (otpCooldown > 0) {
            interval = setInterval(() => {
                setOtpCooldown((prev) => prev - 1);
            }, 1000);
        }
        return () => clearInterval(interval);
    }, [otpCooldown]);

    const handleRequestOtp = async () => {
        if (!user?.email) {
            setError('User email not found.');
            return;
        }
        setLoading(true);
        setError('');
        try {
            await api.post('/auth/request-otp', { email: user.email, purpose: 'change_password' });
            setStep(2);
            setOtpCooldown(60);
            setError(''); 
        } catch (err: any) {
             setError(err.response?.data?.detail || 'Failed to send OTP');
        } finally {
            setLoading(false);
        }
    };

    const handleVerifyOtp = async () => {
        if (!otp) {
            setError('Please enter the OTP');
            return;
        }
        setLoading(true);
        setError('');
        try {
            // Verify OTP Logic
            await api.post('/auth/verify-otp', { email: user?.email, otp, purpose: 'change_password' });
            setStep(3); // Move to password change step
        } catch (err: any) {
             setError(err.response?.data?.detail || 'Invalid OTP');
        } finally {
            setLoading(false);
        }
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        
        if (newPassword !== confirmPassword) {
            setError("Passwords do not match");
            return;
        }

        setLoading(true);
        setError('');
        setSuccess('');
        try {
            await api.post('/auth/change-password', {
                new_password: newPassword,
                otp
            });
            setSuccess('Password changed successfully. Redirecting to profile...');
            setNewPassword('');
            setConfirmPassword('');
            setOtp('');
            
            setTimeout(() => {
                navigate('/profile');
            }, 2000);
            
        } catch (err: any) {
             setError(err.response?.data?.detail || 'Failed to change password');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{ maxWidth: '30rem', margin: '0 auto' }}>
            <h2 className="page-title">
                <ShieldAlert size={24} /> CHANGE PASSWORD
            </h2>
            <Card className="glass-card">
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    <div style={{ textAlign: 'center', marginBottom: '1rem' }}>
                         <p style={{ color: 'hsl(var(--text-secondary))' }}>
                            Authenticated as <strong>{user?.username}</strong>
                         </p>
                    </div>

                    {step === 1 && (
                        <div style={{ textAlign: 'center' }}>
                             <p>To change your password, we need to verify your identity via email OTP.</p>
                             <Button 
                                type="button" 
                                onClick={handleRequestOtp} 
                                disabled={loading || otpCooldown > 0} 
                                className="w-full"
                                style={{ marginTop: '1rem' }}
                            >
                                {loading ? 'SENDING...' : otpCooldown > 0 ? `RESEND IN ${otpCooldown}s` : 'SEND OTP'}
                            </Button>
                        </div>
                    )}

                    {step === 2 && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                            <div style={{ padding: '0.75rem', backgroundColor: 'hsla(var(--color-primary), 0.1)', borderRadius: '0.5rem', textAlign: 'center' }}>
                                <p style={{ fontSize: '0.875rem', color: 'hsl(var(--color-primary))' }}>
                                    ✓ OTP Sent to {user?.email}
                                </p>
                             </div>
                             
                             <Input
                                icon={<Mail size={18} />}
                                placeholder="Enter 6-digit OTP"
                                value={otp}
                                onChange={(e) => setOtp(e.target.value)}
                                required
                            />
                            
                             <Button 
                                type="button" 
                                onClick={handleVerifyOtp} 
                                disabled={loading} 
                                className="w-full"
                            >
                                {loading ? 'VERIFYING...' : 'VERIFY OTP'}
                            </Button>
                            
                             <button 
                                type="button" 
                                onClick={() => setStep(1)} 
                                style={{ background: 'none', border: 'none', color: 'hsl(var(--text-secondary))', cursor: 'pointer', fontSize: '0.875rem', textDecoration: 'underline', width: '100%' }}
                            >
                                Cancel / Resend
                            </button>
                        </div>
                    )}

                    {step === 3 && (
                        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                            <div style={{ padding: '0.75rem', backgroundColor: 'hsla(var(--color-success), 0.1)', borderRadius: '0.5rem', textAlign: 'center' }}>
                                <p style={{ fontSize: '0.875rem', color: 'hsl(var(--color-success))' }}>
                                    ✓ OTP Verified
                                </p>
                             </div>

                             <div style={{ position: 'relative' }}>
                                <Input
                                    icon={<Lock size={18} />}
                                    type={showPassword ? "text" : "password"}
                                    placeholder="New Password"
                                    value={newPassword}
                                    onChange={(e) => setNewPassword(e.target.value)}
                                    required
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    style={{
                                        position: 'absolute',
                                        right: '10px',
                                        top: '50%',
                                        transform: 'translateY(-50%)',
                                        background: 'none',
                                        border: 'none',
                                        color: 'hsl(var(--text-secondary))',
                                        cursor: 'pointer',
                                        zIndex: 10
                                    }}
                                >
                                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                                </button>
                             </div>
                            
                             <div style={{ position: 'relative' }}>
                                <Input
                                    icon={<Lock size={18} />}
                                    type={showPassword ? "text" : "password"}
                                    placeholder="Confirm New Password"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    required
                                />
                                {/* We can omit the toggle here or include it. Usually one toggle works for both if the intention is just 'show passwords', or per-field. I'll use the same state for both for simplicity as they should match. */}
                             </div>

                            <Button type="submit" variant="primary" disabled={loading}>
                                {loading ? 'UPDATING...' : 'CHANGE PASSWORD'}
                            </Button>
                        </form>
                    )}
                    
                    {error && <div style={{ color: '#ef4444', textAlign: 'center', fontSize: '0.875rem' }}>{error}</div>}
                    {success && <div style={{ color: '#4ade80', textAlign: 'center', fontSize: '0.875rem' }}>{success}</div>}
                </div>
            </Card>
        </div>
    );
};
