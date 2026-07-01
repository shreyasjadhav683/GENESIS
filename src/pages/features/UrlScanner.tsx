
import React, { useState } from 'react';
import { Card } from '../../components/Card';
import { Input } from '../../components/Input';
import { Button } from '../../components/Button';
import { ScanResultViewer } from '../../components/ScanResultViewer';
import { 
    Link, Zap, RefreshCw, Search, History, AlertTriangle
} from 'lucide-react';
import { ScanHistoryTable } from '../../components/ScanHistoryTable';
import { ExportButton } from '../../components/ExportButton';
import type { ExportData } from '../../utils/pdfExport';
export const UrlScanner = () => {
    const [url, setUrl] = useState('');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<any>(null);
    const [error, setError] = useState<string | null>(null);
    const [showHistory, setShowHistory] = useState(false);

    const handleScan = async (e: React.FormEvent) => {
        e.preventDefault();
        const trimmedUrl = url.trim();
        if (!trimmedUrl) return;
        
        setLoading(true);
        setError(null);
        setResult(null);

        try {
            const token = localStorage.getItem('token');
            const response = await fetch(`http://127.0.0.1:8000/api/v1/ip/url?url=${encodeURIComponent(trimmedUrl)}`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.detail || `Scan failed: ${response.status} ${response.statusText}`);
            }

            const data = await response.json();
            setResult(data);
        } catch (err: any) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const sha = result?.security_headers_analysis;

    return (
        <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
            {/* Page Header */}
            <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div className="page-header-icon" style={{ background: 'hsla(var(--color-secondary), 0.1)', color: 'hsl(var(--color-secondary))' }}>
                        <Search size={28} />
                    </div>
                    <div>
                        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>URL Scanner</h1>
                        <p style={{ color: 'hsl(var(--text-secondary))', margin: 0, fontSize: '0.9rem' }}>Aggressive deep scan: Phishing, Malware, SSL, Headers, Threat Intel & WHOIS</p>
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
                                    <ScanHistoryTable type="URL" onDelete={() => {}} />
                                </div>
                            </div>
                        </>
                    )}
                </div>
            </div>

            {/* Search Form */}
            <Card style={{ marginBottom: '1.5rem' }}>
                <form onSubmit={handleScan} style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end' }}>
                    <div style={{ flex: 1 }}>
                        <Input 
                            label="Target URL" 
                            placeholder="https://suspicious-link.com" 
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            icon={<Link size={18} />}
                            required
                        />
                    </div>
                    <Button type="submit" isLoading={loading} variant="primary">
                        <Zap size={18} />
                        Aggressive Scan
                    </Button>
                </form>
            </Card>

            {/* Error Display */}
            {error && (
                <div style={{ 
                    padding: '1rem', 
                    marginBottom: '1.5rem',
                    background: 'hsl(var(--color-error-light))', 
                    border: '1px solid hsla(var(--color-error), 0.3)', 
                    borderRadius: 'var(--radius-lg)', 
                    color: 'hsl(var(--color-error))', 
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.75rem'
                }}>
                    <AlertTriangle size={20} />
                    {error}
                </div>
            )}

            {/* Results */}
            {result && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    
                    {/* Actions Bar */}
                    {/* Actions Bar */}
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                        <ExportButton 
                            getPDFData={() => {
                                const tables: Array<{ title: string; headers: string[]; rows: (string | number)[][] }> = [];
                                
                                if (result.redirect_chain?.length > 0) {
                                    tables.push({
                                        title: 'Redirect Chain',
                                        headers: ['Step', 'Status', 'URL'],
                                        rows: result.redirect_chain.map((r: any, idx: number) => [idx + 1, r.status, r.url])
                                    });
                                }
                                
                                if (sha?.headers?.length > 0) {
                                    tables.push({
                                        title: 'Security Headers',
                                        headers: ['Status', 'Header', 'Value'],
                                        rows: sha.headers.map((h: any) => [h.status.toUpperCase(), h.name, h.value || 'Not set'])
                                    });
                                }

                                if (result.flags?.length > 0) {
                                    tables.push({
                                        title: 'Threat Flags',
                                        headers: ['#', 'Flag'],
                                        rows: result.flags.map((f: string, i: number) => [i + 1, f])
                                    });
                                }
                                
                                return {
                                    title: 'URL Aggressive Scan Report',
                                    subtitle: result.url || result.final_url,
                                    summary: {
                                        'Target': result.url,
                                        'Final URL': result.final_url || '',
                                        'Scan Type': 'Aggressive URL Scan',
                                        'Date': new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
                                        'Risk Score': `${result.risk_score}/100`,
                                        'Risk Level': result.risk_level || 'Unknown',
                                        'Verdict': result.malicious ? 'MALICIOUS' : 'SAFE',
                                        'Domain': result.domain || '',
                                        'IP Address': result.ip_address || 'N/A',
                                        'Security Headers Grade': sha?.grade || 'N/A',
                                        'Domain Age': result.domain_info?.age_days != null ? `${result.domain_info.age_days} days` : 'N/A',
                                    },
                                    tables,
                                    flags: result.flags || [],
                                } as ExportData;
                            }}
                            getJSONData={() => result}
                        />
                        <Button onClick={() => { setResult(null); setUrl(''); }} variant="secondary" size="sm">
                            <RefreshCw size={16} />
                            New Scan
                        </Button>
                    </div>

                    <ScanResultViewer 
                        scanType="URL" 
                        target={url} 
                        result={result} 
                        createdAt={new Date().toISOString()}
                    />

                </div>
            )}


        </div>
    );
};
