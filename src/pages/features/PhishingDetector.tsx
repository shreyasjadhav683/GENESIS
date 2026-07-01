
import React, { useState } from 'react';
import { Card } from '../../components/Card';
import { Input } from '../../components/Input';
import { Button } from '../../components/Button';
import { 
    Fish, AlertTriangle, Link, Zap, RefreshCw, History
} from 'lucide-react';
import { api } from '../../services/api';
import { ScanResultViewer } from '../../components/ScanResultViewer';
import { ScanHistoryTable } from '../../components/ScanHistoryTable';
import { ExportButton } from '../../components/ExportButton';

interface PhishingIndicator {
    name: string;
    detected: boolean;
    severity: 'high' | 'medium' | 'low';
    category?: string;
    description: string;
}



export const PhishingDetector = () => {
    const [url, setUrl] = useState('');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<any>(null);
    const [error, setError] = useState<string | null>(null);
    const [showHistory, setShowHistory] = useState(false);

    const analyzeUrl = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!url.trim()) {
            setError("Please enter a URL to analyze");
            return;
        }

        setLoading(true);
        setError(null);
        setResult(null);

        try {
            const response = await api.get(`/scan/phishing-check?url=${encodeURIComponent(url.trim())}`);
            if (response.data.error) {
                setError(response.data.error);
            } else {
                setResult(response.data);
            }
        } catch (err: any) {
            setError(err.response?.data?.detail || err.message || 'Failed to analyze URL');
        } finally {
            setLoading(false);
        }
    };

    const detectedIndicators = result?.indicators?.filter((i: PhishingIndicator) => i.detected) || [];




    return (
        <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
            {/* Page Header */}
            <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div className="page-header-icon" style={{ background: 'hsla(var(--color-warning), 0.1)', color: 'hsl(var(--color-warning))' }}>
                        <Fish size={28} />
                    </div>
                    <div>
                        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Phishing Detector</h1>
                        <p style={{ color: 'hsl(var(--text-secondary))', margin: 0, fontSize: '0.9rem' }}>Aggressive 12-phase phishing analysis with live scanning</p>
                    </div>
                </div>
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
                                    <ScanHistoryTable type="PHISHING" onDelete={() => {}} />
                                </div>
                            </div>
                        </>
                    )}
                </div>
            </div>

            {/* Input Card */}
            <Card style={{ marginBottom: '1.5rem' }}>
                <form onSubmit={analyzeUrl} style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end' }}>
                    <div style={{ flex: 1 }}>
                        <Input 
                            label="Suspicious URL"
                            placeholder="https://suspicious-link.com/login"
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            icon={<Link size={18} />}
                            required
                        />
                    </div>
                    <Button type="submit" isLoading={loading} variant="primary">
                        <Zap size={18} />
                        {loading ? 'Scanning...' : 'Deep Analyze'}
                    </Button>
                </form>
                {loading && (
                    <div style={{ marginTop: '1rem' }}>
                        <p style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))', marginBottom: '0.5rem' }}>
                            Running 12-phase aggressive scan (URL, connection, DNS, SSL, WHOIS, headers, HTML, forms, brand, malware, threat intel, Safe Browsing)...
                        </p>
                        <div style={{ height: '3px', borderRadius: '2px', background: 'hsl(var(--bg-secondary))', overflow: 'hidden' }}>
                            <div style={{ 
                                height: '100%', width: '60%', borderRadius: '2px',
                                background: 'linear-gradient(90deg, hsl(var(--color-primary)), hsl(var(--color-secondary)))',
                                animation: 'shimmer 1.5s infinite'
                            }} />
                        </div>
                    </div>
                )}
            </Card>

            {/* Error */}
            {error && (
                <div style={{ 
                    padding: '1rem', marginBottom: '1.5rem',
                    background: 'hsl(var(--color-error-light))', 
                    border: '1px solid hsla(var(--color-error), 0.3)', 
                    borderRadius: 'var(--radius-lg)', 
                    color: 'hsl(var(--color-error))', fontWeight: 600,
                    display: 'flex', alignItems: 'center', gap: '0.75rem'
                }}>
                    <AlertTriangle size={20} /> {error}
                </div>
            )}

            {/* Results */}
            {result && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    {/* Actions Bar */}
                    <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '0.5rem' }}>
                        <ExportButton 
                            getPDFData={() => {
                                const tables: Array<{ title: string; headers: string[]; rows: (string | number)[][] }> = [];
                                if (result.indicators?.length > 0) {
                                    tables.push({
                                        title: 'Phishing Indicators',
                                        headers: ['Status', 'Indicator', 'Severity', 'Category', 'Description'],
                                        rows: result.indicators.map((i: PhishingIndicator) => [
                                            i.detected ? 'DETECTED' : 'SAFE',
                                            i.name, i.severity.toUpperCase(), i.category || '', i.description
                                        ])
                                    });
                                }
                                if (result.flags?.length > 0) {
                                    tables.push({
                                        title: 'Critical Flags',
                                        headers: ['Flag'],
                                        rows: result.flags.map((f: string) => [f])
                                    });
                                }
                                return {
                                    title: 'Phishing Analysis Report',
                                    subtitle: result.url || url,
                                    summary: {
                                        'Target': result.url || url,
                                        'Final URL': result.final_url || '',
                                        'Scan Type': 'Aggressive Phishing Detection',
                                        'Date': new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
                                        'Verdict': result.verdict || '',
                                        'Risk Score': `${result.risk_score}/100`,
                                        'Risk Level': result.risk_level,
                                        'Domain': result.domain,
                                        'IP Address': result.ip_address || '',
                                    },
                                    tables,
                                    flags: detectedIndicators.map((i: PhishingIndicator) => `${i.name} - ${i.description}`)
                                };
                            }}
                            getJSONData={() => result}
                        />
                        <Button onClick={() => { setResult(null); setUrl(''); }} variant="secondary" size="sm">
                            <RefreshCw size={16} /> New Analysis
                        </Button>
                    </div>

                    <ScanResultViewer 
                        scanType="PHISHING" 
                        target={url} 
                        result={result} 
                        createdAt={new Date().toISOString()}
                    />
                </div>
            )}



        </div>
    );
};
