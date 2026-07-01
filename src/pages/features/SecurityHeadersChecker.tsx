
import React, { useState } from 'react';
import { Card } from '../../components/Card';
import { Input } from '../../components/Input';
import { Button } from '../../components/Button';
import { Shield, AlertTriangle, Globe, RefreshCw, Zap, History } from 'lucide-react';
import { api } from '../../services/api';
import { ScanResultViewer } from '../../components/ScanResultViewer';
import { ScanHistoryTable } from '../../components/ScanHistoryTable';
import { ExportButton } from '../../components/ExportButton';



export const SecurityHeadersChecker = () => {
    const [url, setUrl] = useState('');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<any>(null);
    const [error, setError] = useState<string | null>(null);
    const [showHistory, setShowHistory] = useState(false);

    const checkHeaders = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!url.trim()) {
            setError("Please enter a URL");
            return;
        }

        setLoading(true);
        setError(null);
        setResult(null);

        try {
            const response = await api.get(`/scan/security-headers?url=${encodeURIComponent(url)}`);
            
            if (response.data.error) {
                setError(response.data.error);
            } else {
                setResult(response.data);
            }
        } catch (err: any) {
            setError(err.response?.data?.detail || err.message || 'Failed to check security headers');
        } finally {
            setLoading(false);
        }
    };



    return (
        <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
            {/* Page Header */}
            <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div className="page-header-icon" style={{ background: 'hsla(var(--color-success), 0.1)', color: 'hsl(var(--color-success))' }}>
                        <Shield size={28} />
                    </div>
                    <div>
                        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Security Headers Checker</h1>
                        <p style={{ color: 'hsl(var(--text-secondary))', margin: 0, fontSize: '0.9rem' }}>Analyze HTTP security headers for any website</p>
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
                                    <ScanHistoryTable type="SECURITY_HEADERS" onDelete={() => {}} />
                                </div>
                            </div>
                        </>
                    )}
                </div>
            </div>

            {/* Input Card */}
            <Card style={{ marginBottom: '1.5rem' }}>
                <form onSubmit={checkHeaders} style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end' }}>
                    <div style={{ flex: 1 }}>
                        <Input 
                            label="Website URL"
                            placeholder="https://example.com"
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            icon={<Globe size={18} />}
                            required
                        />
                    </div>
                    <Button type="submit" isLoading={loading} variant="primary">
                        <Zap size={18} />
                        Check Headers
                    </Button>
                </form>
            </Card>

            {/* Error */}
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
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                        <ExportButton 
                            getPDFData={() => {
                                const tables: Array<{ title: string; headers: string[]; rows: (string | number)[][] }> = [];
                                
                                if (result.headers && result.headers.length > 0) {
                                    tables.push({
                                        title: 'Header Analysis',
                                        headers: ['Status', 'Header Name', 'Value', 'Description'],
                                        rows: result.headers.map((h: any) => [
                                            h.status.toUpperCase(),
                                            h.name,
                                            h.value || 'Not set',
                                            h.description
                                        ])
                                    });
                                }
                                
                                return {
                                    title: 'Security Headers Report',
                                    subtitle: result.final_url || url,
                                    summary: {
                                        'Target': result.final_url || url,
                                        'Scan Type': 'Security Headers',
                                        'Date': new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
                                        'Security Grade': result.score >= 80 ? 'A' : result.score >= 60 ? 'C' : 'F', // simplified for export
                                        'Score': `${result.score}/100`,
                                        'Headers Present': result.present_count,
                                        'Headers Missing': result.missing_count,
                                    },
                                    tables,
                                    flags: result.headers
                                        ?.filter((h: any) => h.status === 'missing')
                                        .map((h: any) => `Missing: ${h.name} - ${h.recommendation || h.description}`) || []
                                };
                            }}
                            getJSONData={() => result}
                        />
                        <Button onClick={() => { setResult(null); setUrl(''); }} variant="secondary" size="sm">
                            <RefreshCw size={16} />
                            New Check
                        </Button>
                    </div>
                    
                    <ScanResultViewer 
                        scanType="SECURITY_HEADERS" 
                        target={url} 
                        result={result} 
                        createdAt={new Date().toISOString()}
                    />
                </div>
            )}


        </div>
    );
};
