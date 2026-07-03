import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

export default function AdminLogin() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]     = useState('');
  const [loading, setLoading] = useState(false);
  const [showPass, setShowPass] = useState(false);

  // If already logged in as admin, go straight to panel
  useEffect(() => {
    if (localStorage.getItem('admin_token')) navigate('/admin', { replace: true });
  }, [navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!username.trim() || !password.trim()) {
      setError('Please enter both username and password.');
      return;
    }
    setLoading(true);
    try {
      const res = await axios.post(`${API_URL}/admin/login`, { username, password });
      localStorage.setItem('admin_token', res.data.access_token);
      localStorage.setItem('admin_info', JSON.stringify(res.data.admin));
      navigate('/admin', { replace: true });
    } catch (err: any) {
      const msg = err.response?.data?.detail || 'Login failed. Check your credentials.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={s.page}>
      {/* Background grid */}
      <div style={s.grid} />

      {/* Glowing orbs */}
      <div style={{ ...s.orb, top: '-120px', left: '-120px', background: 'radial-gradient(circle, #dc262640 0%, transparent 70%)' }} />
      <div style={{ ...s.orb, bottom: '-100px', right: '-100px', background: 'radial-gradient(circle, #7c3aed30 0%, transparent 70%)' }} />

      <div style={s.card}>
        {/* Shield icon */}
        <div style={s.iconWrap}>
          <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#dc2626" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>

        <h1 style={s.title}>Admin Portal</h1>
        <p style={s.subtitle}>Genesis Cybersecurity — Restricted Access</p>

        <div style={s.divider} />

        <form onSubmit={handleSubmit} style={s.form}>
          {/* Username */}
          <div style={s.field}>
            <label style={s.label}>Username or Email</label>
            <div style={s.inputWrap}>
              <svg style={s.inputIcon} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="2">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
              </svg>
              <input
                style={s.input}
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="admin username"
                autoComplete="username"
                autoFocus
              />
            </div>
          </div>

          {/* Password */}
          <div style={s.field}>
            <label style={s.label}>Password</label>
            <div style={s.inputWrap}>
              <svg style={s.inputIcon} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
              <input
                style={s.input}
                type={showPass ? 'text' : 'password'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••"
                autoComplete="current-password"
              />
              <button type="button" style={s.eyeBtn} onClick={() => setShowPass(v => !v)} tabIndex={-1}>
                {showPass ? '🙈' : '👁️'}
              </button>
            </div>
          </div>

          {/* Error */}
          {error && (
            <div style={s.errorBox}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f87171" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
              <span>{error}</span>
            </div>
          )}

          <button style={{ ...s.btn, opacity: loading ? 0.7 : 1 }} type="submit" disabled={loading}>
            {loading ? (
              <span style={{ display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center' }}>
                <span style={s.spinner} /> Authenticating...
              </span>
            ) : 'Sign In to Admin Panel'}
          </button>
        </form>

        <div style={s.divider} />

        <p style={s.warning}>
          🔒 This portal is restricted to authorized administrators only.
          Unauthorized access attempts are logged.
        </p>

        <button style={s.backLink} onClick={() => navigate('/login')}>
          ← Back to regular login
        </button>
      </div>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  page: {
    minHeight: '100vh',
    background: '#020617',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '24px',
    fontFamily: 'Inter, Arial, sans-serif',
    position: 'relative',
    overflow: 'hidden',
  },
  grid: {
    position: 'absolute', inset: 0,
    backgroundImage: 'linear-gradient(rgba(220,38,38,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(220,38,38,0.03) 1px, transparent 1px)',
    backgroundSize: '40px 40px',
    pointerEvents: 'none',
  },
  orb: {
    position: 'absolute', width: 400, height: 400, borderRadius: '50%',
    pointerEvents: 'none',
  },
  card: {
    background: '#0a0f1e',
    border: '1px solid #1e1e2e',
    borderRadius: 16,
    padding: '40px 36px',
    width: '100%',
    maxWidth: 420,
    position: 'relative',
    boxShadow: '0 0 60px rgba(220,38,38,0.1), 0 25px 50px rgba(0,0,0,0.5)',
  },
  iconWrap: {
    width: 64, height: 64, borderRadius: '50%',
    background: 'rgba(220,38,38,0.1)',
    border: '1px solid rgba(220,38,38,0.3)',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    margin: '0 auto 20px',
  },
  title: {
    margin: 0, fontSize: 26, fontWeight: 700,
    color: '#f1f5f9', textAlign: 'center', letterSpacing: '-0.5px',
  },
  subtitle: {
    margin: '6px 0 0', fontSize: 13,
    color: '#475569', textAlign: 'center',
  },
  divider: {
    height: 1, background: '#1e293b', margin: '24px 0',
  },
  form: { display: 'flex', flexDirection: 'column', gap: 18 },
  field: { display: 'flex', flexDirection: 'column', gap: 6 },
  label: { fontSize: 12, fontWeight: 600, color: '#64748b', letterSpacing: '0.05em', textTransform: 'uppercase' },
  inputWrap: { position: 'relative', display: 'flex', alignItems: 'center' },
  inputIcon: { position: 'absolute', left: 12, pointerEvents: 'none' },
  input: {
    width: '100%', padding: '11px 12px 11px 38px',
    background: '#0f172a', border: '1px solid #1e293b',
    borderRadius: 8, color: '#e2e8f0', fontSize: 14,
    outline: 'none', boxSizing: 'border-box',
    transition: 'border-color 0.2s',
  },
  eyeBtn: {
    position: 'absolute', right: 10,
    background: 'none', border: 'none',
    cursor: 'pointer', fontSize: 14, padding: 4,
  },
  errorBox: {
    display: 'flex', alignItems: 'center', gap: 8,
    background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)',
    borderRadius: 8, padding: '10px 12px',
    color: '#f87171', fontSize: 13,
  },
  btn: {
    padding: '12px',
    background: 'linear-gradient(135deg, #dc2626, #991b1b)',
    border: 'none', borderRadius: 8,
    color: '#fff', fontWeight: 700, fontSize: 15,
    cursor: 'pointer', marginTop: 4,
    boxShadow: '0 4px 20px rgba(220,38,38,0.35)',
    transition: 'opacity 0.2s',
  },
  spinner: {
    width: 14, height: 14,
    border: '2px solid rgba(255,255,255,0.3)',
    borderTop: '2px solid #fff',
    borderRadius: '50%',
    display: 'inline-block',
    animation: 'spin 0.7s linear infinite',
  },
  warning: {
    fontSize: 12, color: '#334155',
    textAlign: 'center', lineHeight: 1.6, margin: 0,
  },
  backLink: {
    display: 'block', margin: '16px auto 0',
    background: 'none', border: 'none',
    color: '#475569', fontSize: 13,
    cursor: 'pointer', textAlign: 'center',
  },
};
