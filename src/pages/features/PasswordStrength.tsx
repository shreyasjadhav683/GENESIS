
import React, { useState } from 'react';
import { Card } from '../../components/Card';
import { Input } from '../../components/Input';
import { Button } from '../../components/Button';
import { Key, ShieldCheck, Zap, RefreshCw, History, AlertTriangle } from 'lucide-react';
import { ScanHistoryTable } from '../../components/ScanHistoryTable';
import { ExportButton } from '../../components/ExportButton';
import { ScanResultViewer } from '../../components/ScanResultViewer';



export const PasswordStrength = () => {
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<any>(null);
    const [error, setError] = useState<string | null>(null);
    const [showHistory, setShowHistory] = useState(false);

    const handleCheck = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(null);
        setResult(null);

        try {
            const token = localStorage.getItem('token');
            const response = await fetch('http://127.0.0.1:8000/api/v1/scan/password-strength', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ password })
            });

            if (!response.ok) throw new Error('Failed to check password strength');
            const data = await response.json();
            setResult(data);
        } catch (err: any) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    // Compute criteria from password
    const criteria = password ? [
        { label: 'Minimum 8 characters', met: password.length >= 8 },
        { label: 'Uppercase letter (A-Z)', met: /[A-Z]/.test(password) },
        { label: 'Lowercase letter (a-z)', met: /[a-z]/.test(password) },
        { label: 'Contains digit (0-9)', met: /\d/.test(password) },
        { label: 'Special character (!@#$...)', met: /[^A-Za-z0-9]/.test(password) },
        { label: '12+ characters (recommended)', met: password.length >= 12 },
    ] : [];

    const [showGenerator, setShowGenerator] = useState(false);
    const [genLength, setGenLength] = useState(16);
    const [genUseSymbols, setGenUseSymbols] = useState(true);
    const [genUseNumbers, setGenUseNumbers] = useState(true);
    const [genUseUpper, setGenUseUpper] = useState(true);

    const generatePassword = () => {
        const lower = 'abcdefghijklmnopqrstuvwxyz';
        const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const numbers = '0123456789';
        const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

        let chars = lower;
        if (genUseUpper) chars += upper;
        if (genUseNumbers) chars += numbers;
        if (genUseSymbols) chars += symbols;

        let generated = '';
        const array = new Uint32Array(genLength);
        window.crypto.getRandomValues(array);
        
        for (let i = 0; i < genLength; i++) {
            generated += chars[array[i] % chars.length];
        }
        setPassword(generated);
        // Auto-check generated password
        setTimeout(() => document.getElementById('analyze-btn')?.click(), 100);
    };

    return (
        <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
            {/* Page Header */}
            <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div className="page-header-icon" style={{ background: 'hsla(var(--color-error), 0.1)', color: 'hsl(var(--color-error))' }}>
                        <Key size={28} />
                    </div>
                    <div>
                        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Password Strength & Safety</h1>
                        <p style={{ color: 'hsl(var(--text-secondary))', margin: 0, fontSize: '0.9rem' }}>Advanced entropy analysis, breach detection, and secure password generation</p>
                    </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginLeft: 'auto' }}>
                    <Button variant="secondary" onClick={() => setShowGenerator(!showGenerator)}>
                        <RefreshCw size={16} />
                        {showGenerator ? 'Hide Generator' : 'Password Generator'}
                    </Button>
                    <div style={{ position: 'relative' }}>
                        <Button 
                            variant="secondary" 
                            onClick={() => setShowHistory(!showHistory)}
                            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                        >
                            <History size={18} />
                            History
                        </Button>

                        {/* History Popover */}
                        {showHistory && (
                            <>
                                {/* Backdrop for outside click */}
                                <div 
                                    style={{ position: 'fixed', inset: 0, zIndex: 90 }} 
                                    onClick={() => setShowHistory(false)}
                                />
                                
                                <div 
                                    className="animate-fade-in-up"
                                    style={{ 
                                        position: 'absolute',
                                        top: 'calc(100% + 10px)',
                                        right: 0,
                                        width: '900px',
                                        maxHeight: '80vh',
                                        background: 'hsl(var(--bg-card))',
                                        border: '1px solid hsl(var(--border-color))',
                                        borderRadius: 'var(--radius-lg)',
                                        boxShadow: 'var(--shadow-xl)',
                                        zIndex: 100,
                                        display: 'flex',
                                        flexDirection: 'column',
                                        overflow: 'hidden'
                                    }}
                                >
                                    <div style={{ 
                                        padding: '1rem',
                                        borderBottom: '1px solid hsl(var(--border-color))',
                                        display: 'flex',
                                        alignItems: 'center',
                                        justifyContent: 'space-between',
                                        background: 'hsl(var(--bg-secondary-light))'
                                    }}>
                                        <h3 style={{ 
                                            fontSize: '0.9rem', 
                                            fontWeight: 700, 
                                            color: 'hsl(var(--text-primary))',
                                            textTransform: 'uppercase',
                                            letterSpacing: '0.05em'
                                        }}>
                                            Start new scan or view history
                                        </h3>
                                    </div>
                                    <div style={{ flex: 1, overflow: 'auto', padding: '1rem' }}>
                                        <ScanHistoryTable type="PASSWORD" onDelete={() => {}} />
                                    </div>
                                </div>
                            </>
                        )}
                    </div>
                </div>
            </div>

            {/* Password Generator Card */}
            {showGenerator && (
                <Card style={{ marginBottom: '1.5rem', border: '1px solid hsl(var(--color-primary))', background: 'hsla(var(--color-primary), 0.03)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <h3 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                <Zap size={18} style={{ color: 'hsl(var(--color-primary))' }} />
                                Secure Password Generator
                            </h3>
                        </div>
                        <div style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap' }}>
                            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.9rem' }}>
                                Length: <b>{genLength}</b>
                                <input 
                                    type="range" min="8" max="64" value={genLength} 
                                    onChange={(e) => setGenLength(parseInt(e.target.value))}
                                    style={{ accentColor: 'hsl(var(--color-primary))' }}
                                />
                            </label>
                            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.9rem' }}>
                                <input type="checkbox" checked={genUseUpper} onChange={e => setGenUseUpper(e.target.checked)} /> Uppercase
                            </label>
                            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.9rem' }}>
                                <input type="checkbox" checked={genUseNumbers} onChange={e => setGenUseNumbers(e.target.checked)} /> Numbers
                            </label>
                            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.9rem' }}>
                                <input type="checkbox" checked={genUseSymbols} onChange={e => setGenUseSymbols(e.target.checked)} /> Symbols
                            </label>
                            <Button onClick={generatePassword} size="sm" variant="primary" style={{ marginLeft: 'auto' }}>
                                Generate & Analyze
                            </Button>
                        </div>
                    </div>
                </Card>
            )}

            {/* Input Card */}
            <Card style={{ marginBottom: '1.5rem' }}>
                <form onSubmit={handleCheck} style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end' }}>
                    <div style={{ flex: 1 }}>
                        <Input 
                            type="password"
                            label="Test Password" 
                            placeholder="Enter password to analyze..." 
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            icon={<Key size={18} />}
                            required
                        />
                    </div>
                    <Button id="analyze-btn" type="submit" isLoading={loading} variant="primary">
                        <ShieldCheck size={18} />
                        Analyze Safety
                    </Button>
                </form>
            </Card>

            {/* Error */}
            {error && (
                <div style={{ 
                    padding: '1rem', 
                    background: 'hsl(var(--color-error-light))', 
                    border: '1px solid hsla(var(--color-error), 0.3)', 
                    borderRadius: 'var(--radius-lg)', 
                    color: 'hsl(var(--color-error))', 
                    fontWeight: 600,
                    display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem'
                }}>
                    <AlertTriangle size={20} />
                    {error}
                </div>
            )}

            {/* Results */}
            {result && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    
                    {/* Actions Bar */}
                    <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '0.5rem' }}>
                        <ExportButton 
                            getPDFData={() => ({
                                title: 'Password Strength Report',
                                subtitle: 'Safety Analysis',
                                summary: {
                                    'Target': '[Hidden]',
                                    'Date': new Date().toLocaleString(),
                                    'Strength': `${result.score}/4`,
                                    'Breach Status': result.breach_count > 0 ? `COMPROMISED (${result.breach_count})` : 'Clean'
                                },
                                tables: []
                            })}
                            getJSONData={() => ({ ...result, criteria, password: '[REDACTED]' })}
                        />
                        <Button onClick={() => { setResult(null); setPassword(''); }} variant="secondary" size="sm">
                            <RefreshCw size={16} />
                            Clear
                        </Button>
                    </div>

                    <ScanResultViewer 
                        scanType="PASSWORD_STRENGTH" 
                        target="[HIDDEN]" 
                        result={{ ...result, criteria }} 
                        createdAt={new Date().toISOString()}
                    />
                </div>
            )}


        </div>
    );
};
