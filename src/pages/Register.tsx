import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Card } from '../components/Card';
import { Input } from '../components/Input';
import { Button } from '../components/Button';
import { useAuth } from '../context/AuthContext';
import { Lock, User, Shield, HelpCircle, Cpu, Mail } from 'lucide-react';
import { ThemeToggle } from '../components/ThemeToggle';
import { api } from '../services/api';

export const Register: React.FC = () => {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [securityQuestion, setSecurityQuestion] = useState('What was your first pet\'s name?');
  const [securityAnswer, setSecurityAnswer] = useState('');
  
  // OTP State
  const [otp, setOtp] = useState('');
  const [isOtpSent, setIsOtpSent] = useState(false);
  const [otpCooldown, setOtpCooldown] = useState(0);

  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const { register } = useAuth();

  useEffect(() => {
    let interval: any;
    if (otpCooldown > 0) {
      interval = setInterval(() => {
        setOtpCooldown((prev) => prev - 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [otpCooldown]);

  const handleSendOtp = async () => {
      if (!email) {
          setError('Please enter an email address first.');
          return;
      }
      setLoading(true);
      setError('');
      try {
          await api.post('/auth/request-otp', { email, purpose: 'register' });
          setIsOtpSent(true);
          setOtpCooldown(60);
          alert('OTP sent to your email.');
      } catch (err: any) {
          setError(err.response?.data?.detail || 'Failed to send OTP.');
      } finally {
          setLoading(false);
      }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (!isOtpSent) {
        // Automatically try to send OTP if not sent yet? 
        // Or just force them to click Verify.
        // Let's force verify for better UX clarity.
        setError('Please verify your email first.');
        return;
    }
    if (!otp) {
        setError('Please enter the verification code sent to your email.');
        return;
    }

    setLoading(true);
    try {
      // Pass OTP to register function (which needs to be updated to accept it, 
      // or we pass it in the user object if the context function just passes it through)
      // Inspecting AuthContext, it calls api.post('/auth/register', userData).
      // So we just add otp to the object.
      await register({
        username,
        email,
        password,
        security_question: securityQuestion,
        security_answer: securityAnswer,
        otp
      });
      // Redirect to login after successful registration
      navigate('/login');
    } catch (err: any) {
        console.error(err);
      setError(err.response?.data?.detail || 'Registration failed. Try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-bg-blob" style={{ top: '20%', left: '30%', backgroundColor: 'hsla(var(--color-primary), 0.2)' }}></div>
      <div className="login-bg-blob" style={{ bottom: '20%', right: '30%', backgroundColor: 'hsla(var(--color-secondary), 0.2)' }}></div>

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
            <h1 className="login-title">GENESIS</h1>
            <p style={{ color: 'hsl(var(--color-primary))', letterSpacing: '0.3em', fontSize: '0.75rem', fontWeight: 'bold', textTransform: 'uppercase', opacity: 0.8 }}>
                Secure System Access
            </p>
        </div>

        <Card className="login-card" style={{ borderColor: 'hsla(var(--color-primary), 0.3)', backgroundColor: 'hsla(var(--bg-card), 0.8)' }}>
            <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                <h2 style={{ textAlign: 'center', margin: 0, color: 'hsl(var(--text-primary))' }}>CREATE ACCOUNT</h2>
                
                <Input
                    icon={<User size={18} />}
                    placeholder="Username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                />
                 
                 <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-start' }}>
                    <div style={{ flex: 1 }}>
                        <Input
                            icon={<Shield size={18} />}
                            placeholder="Email Address"
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                        />
                    </div>
                    <Button 
                        type="button" 
                        variant="secondary" 
                        onClick={handleSendOtp}
                        disabled={otpCooldown > 0 || loading || !email}
                        style={{ whiteSpace: 'nowrap', height: '42px' }}
                    >
                        {otpCooldown > 0 ? `${otpCooldown}s` : 'Verify'}
                    </Button>
                 </div>

                 {isOtpSent && (
                    <div className="animate-slide-in-bottom">
                         <Input
                            icon={<Mail size={18} />}
                            placeholder="Enter Email OTP"
                            value={otp}
                            onChange={(e) => setOtp(e.target.value)}
                            required
                        />
                        <p style={{ fontSize: '0.7rem', color: '#4ade80', marginTop: '0.25rem', paddingLeft: '0.5rem' }}>
                            ✓ OTP Sent to {email}
                        </p>
                    </div>
                 )}
                
                <div style={{ display: 'flex', gap: '1rem' }}>
                     <Input
                        icon={<Lock size={18} />}
                        placeholder="Password"
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                        className="w-full"
                    />
                     <Input
                        icon={<Lock size={18} />}
                        placeholder="Confirm"
                        type="password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        required
                        className="w-full"
                    />
                </div>

                <div className="input-group">
                    <label className="input-label" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <HelpCircle size={14} /> Security Question
                    </label>
                    <select 
                        className="input-field"
                        value={securityQuestion}
                        onChange={(e) => setSecurityQuestion(e.target.value)}
                        style={{ padding: '0.5rem', borderRadius: '0.25rem' }}
                    >
                        <option>What was your first pet's name?</option>
                        <option>What is your mother's maiden name?</option>
                        <option>What city were you born in?</option>
                    </select>
                </div>

                <Input
                    icon={<HelpCircle size={18} />}
                    placeholder="Security Answer"
                    value={securityAnswer}
                    onChange={(e) => setSecurityAnswer(e.target.value)}
                    required
                    type="password" // Hide answer
                />

                {error && <div style={{ color: '#ef4444', textAlign: 'center', fontSize: '0.875rem' }}>{error}</div>}

                <Button type="submit" variant="primary" className="w-full" disabled={loading}>
                    {loading ? 'PROCESSING...' : 'COMPLETE REGISTRATION'}
                </Button>
                
                <div style={{ textAlign: 'center', fontSize: '0.875rem' }}>
                    <Link to="/login" style={{ color: 'hsl(var(--color-primary))', textDecoration: 'none' }}>
                        Already have an account? Login
                    </Link>
                </div>
            </form>
        </Card>
      </div>
    </div>
  );
};
