
import React, { useState } from 'react';
import { Card } from '../components/Card';
import { Input } from '../components/Input';
import { Button } from '../components/Button';
import { Lock, User, Shield, ArrowRight } from 'lucide-react';
import { ThemeToggle } from '../components/ThemeToggle';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';

export const Login = () => {
    const navigate = useNavigate();
    const { login } = useAuth();
    const [loading, setLoading] = useState(false);
    const [step, setStep] = useState<1 | 2>(1);
    const [formData, setFormData] = useState({ username: '', password: '', otp: '' });
    const [error, setError] = useState<string | null>(null);

    const handleInit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(null);

        try {
            const formDataBody = new URLSearchParams();
            formDataBody.append('username', formData.username);
            formDataBody.append('password', formData.password);

            await api.post('/auth/login/init', formDataBody, {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });
            setStep(2);
        } catch (err: any) {
            setError(err.response?.data?.detail || 'Authentication failed');
        } finally {
            setLoading(false);
        }
    };

    const handleVerify = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(null);

        try {
            const response = await api.post('/auth/login/verify', {
                username: formData.username,
                password: formData.password,
                otp: formData.otp
            });

            await login(response.data.access_token);
            navigate('/dashboard');
        } catch (err: any) {
            setError(err.response?.data?.detail || 'Invalid OTP');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="login-container">
            {/* Animated Background */}
            <div style={{ 
                position: 'absolute', 
                inset: 0, 
                overflow: 'hidden', 
                pointerEvents: 'none' 
            }}>
                {/* Primary Glow */}
                <div 
                    className="login-bg-blob animate-pulse"
                    style={{ 
                        top: '-15%', 
                        left: '-10%', 
                        width: '50vh', 
                        height: '50vh', 
                        background: 'var(--gradient-primary)',
                        opacity: 0.15
                    }}
                />
                {/* Secondary Glow */}
                <div 
                    className="login-bg-blob animate-pulse"
                    style={{ 
                        bottom: '-20%', 
                        right: '-5%', 
                        width: '60vh', 
                        height: '60vh', 
                        background: 'var(--gradient-secondary)',
                        animationDelay: '1s',
                        opacity: 0.15
                    }}
                />
                {/* Accent Glow */}
                <div 
                    className="login-bg-blob animate-pulse"
                    style={{ 
                        top: '40%', 
                        right: '20%', 
                        width: '30vh', 
                        height: '30vh', 
                        background: 'var(--gradient-accent)',
                        animationDelay: '2s',
                        opacity: 0.1
                    }}
                />
            </div>

            {/* Theme Toggle */}
            <div style={{ position: 'absolute', top: '1.5rem', right: '1.5rem', zIndex: 50 }}>
                <ThemeToggle />
            </div>

            {/* Main Content */}
            <div className="login-content">
                {/* Logo & Header */}
                <div className="login-header">
                    <div style={{ 
                        display: 'inline-flex', 
                        alignItems: 'center', 
                        justifyContent: 'center', 
                        padding: '1.25rem', 
                        borderRadius: 'var(--radius-2xl)', 
                        background: 'var(--gradient-accent)',
                        marginBottom: '1.5rem',
                        boxShadow: 'var(--glow-primary)'
                    }}>
                        <Shield size={40} color="white" />
                    </div>
                    <h1 className="login-title">GENESIS</h1>
                    <p style={{ 
                        color: 'hsl(var(--text-secondary))', 
                        letterSpacing: '0.2em', 
                        fontSize: '0.8rem', 
                        fontWeight: 500, 
                        textTransform: 'uppercase',
                        marginTop: '0.5rem'
                    }}>
                        Cybersecurity Platform
                    </p>
                </div>

                {/* Login Card */}
                <Card 
                    variant="glass"
                    style={{ 
                        borderColor: 'hsla(var(--color-primary), 0.2)',
                        boxShadow: 'var(--shadow-xl)'
                    }}
                >
                    {step === 1 ? (
                        <form onSubmit={handleInit} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                            {/* Error Alert */}
                            {error && (
                                <div style={{ 
                                    padding: '0.875rem 1rem', 
                                    background: 'hsl(var(--color-error-light))', 
                                    border: '1px solid hsla(var(--color-error), 0.3)', 
                                    borderRadius: 'var(--radius-md)', 
                                    color: 'hsl(var(--color-error))', 
                                    fontSize: '0.875rem', 
                                    fontWeight: 600,
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '0.5rem'
                                }}>
                                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <circle cx="12" cy="12" r="10"/>
                                        <line x1="12" y1="8" x2="12" y2="12"/>
                                        <line x1="12" y1="16" x2="12.01" y2="16"/>
                                    </svg>
                                    {error}
                                </div>
                            )}

                            {/* Username Input */}
                            <Input
                                placeholder="Enter your username"
                                label="Username"
                                icon={<User size={18} />}
                                value={formData.username}
                                onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                                required
                            />
                            
                            {/* Password Input */}
                            <Input
                                type="password"
                                placeholder="Enter your password"
                                label="Password"
                                icon={<Lock size={18} />}
                                value={formData.password}
                                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                                required
                            />

                            {/* Links */}
                            <div style={{ 
                                display: 'flex', 
                                alignItems: 'center', 
                                justifyContent: 'space-between', 
                                fontSize: '0.8rem'
                            }}>
                                <Link 
                                    to="/register" 
                                    style={{ 
                                        textDecoration: 'none', 
                                        color: 'hsl(var(--color-primary))', 
                                        fontWeight: 600,
                                        transition: 'opacity 0.2s'
                                    }}
                                >
                                    Create Account
                                </Link>
                                <Link 
                                    to="/forgot-password" 
                                    style={{ 
                                        textDecoration: 'none', 
                                        color: 'hsl(var(--text-secondary))',
                                        transition: 'color 0.2s'
                                    }}
                                >
                                    Forgot Password?
                                </Link>
                            </div>

                            {/* Submit Button */}
                            <Button 
                                type="submit" 
                                isLoading={loading} 
                                size="lg" 
                                variant="primary"
                                rightIcon={<ArrowRight size={18} />}
                                style={{ width: '100%', marginTop: '0.5rem' }}
                            >
                                Continue
                            </Button>
                            
                            {/* Admin Link */}
                            <div style={{ textAlign: 'center', marginTop: '1rem' }}>
                                <Link to="/admin-login" style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))', textDecoration: 'none', opacity: 0.7, transition: 'opacity 0.2s' }}>
                                    Administrator Portal
                                </Link>
                            </div>
                        </form>
                    ) : (
                        <form onSubmit={handleVerify} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                            <div style={{ padding: '1rem', background: 'hsla(var(--color-primary), 0.1)', borderRadius: '0.5rem', color: 'hsl(var(--color-primary))', fontSize: '0.9rem', textAlign: 'center', fontWeight: 500 }}>
                                An OTP has been sent to your email. Enter it below to proceed.
                            </div>

                            {/* Error Alert */}
                            {error && (
                                <div style={{ 
                                    padding: '0.875rem 1rem', 
                                    background: 'hsl(var(--color-error-light))', 
                                    border: '1px solid hsla(var(--color-error), 0.3)', 
                                    borderRadius: 'var(--radius-md)', 
                                    color: 'hsl(var(--color-error))', 
                                    fontSize: '0.875rem', 
                                    fontWeight: 600,
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '0.5rem'
                                }}>
                                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <circle cx="12" cy="12" r="10"/>
                                        <line x1="12" y1="8" x2="12" y2="12"/>
                                        <line x1="12" y1="16" x2="12.01" y2="16"/>
                                    </svg>
                                    {error}
                                </div>
                            )}

                            {/* OTP Input */}
                            <Input
                                placeholder="000000"
                                label="Verification Code"
                                icon={<Lock size={18} />}
                                value={formData.otp}
                                onChange={(e) => setFormData({ ...formData, otp: e.target.value })}
                                required
                                maxLength={6}
                                style={{ letterSpacing: '0.2em', fontWeight: 'bold' }}
                            />

                            {/* Submit Button */}
                            <Button 
                                type="submit" 
                                isLoading={loading} 
                                size="lg" 
                                variant="primary"
                                rightIcon={<ArrowRight size={18} />}
                                style={{ width: '100%', marginTop: '0.5rem' }}
                            >
                                Sign In
                            </Button>
                            
                            <button
                                type="button"
                                onClick={() => setStep(1)}
                                disabled={loading}
                                style={{
                                    background: 'none',
                                    border: 'none',
                                    color: 'hsl(var(--text-secondary))',
                                    fontSize: '0.875rem',
                                    cursor: 'pointer',
                                    marginTop: '-0.5rem'
                                }}
                            >
                                ← Back
                            </button>
                        </form>
                    )}
                </Card>
                
                {/* Footer */}
                <div style={{ marginTop: '2rem', textAlign: 'center' }}>
                    <p style={{ 
                        color: 'hsl(var(--text-muted))', 
                        fontSize: '0.75rem', 
                        letterSpacing: '0.05em'
                    }}>
                        Protected by enterprise-grade security
                    </p>
                </div>
            </div>
        </div>
    );
};
