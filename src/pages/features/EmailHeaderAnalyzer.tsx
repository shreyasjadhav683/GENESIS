
import { useState } from 'react';
import { Card } from '../../components/Card';
import { Button } from '../../components/Button';
import { 
    Mail, AlertTriangle, RefreshCw, Zap, History
} from 'lucide-react';
import { api } from '../../services/api';
import { ScanResultViewer } from '../../components/ScanResultViewer';
import { ScanHistoryTable } from '../../components/ScanHistoryTable';
import { ExportButton } from '../../components/ExportButton';


export const EmailHeaderAnalyzer = () => {
    const [headers, setHeaders] = useState('');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<any>(null);  // full response object
    const [error, setError] = useState<string | null>(null);
    const [showHistory, setShowHistory] = useState(false);

    const parseHeaders = async () => {
        if (!headers.trim()) {
            setError("Please paste email headers");
            return;
        }

        setLoading(true);
        setError(null);
        setResult(null);

        try {
            const response = await api.post('/scan/email-headers', null, {
                params: { headers: headers }
            });

            if (response.data.error) {
                setError(response.data.error);
            } else {
                setResult(response.data);
            }
        } catch (err: any) {
            setError(err.response?.data?.detail || err.message || 'Failed to analyze headers');
        } finally {
            setLoading(false);
        }
    };

    const summary = result?.summary;
    const parsedHeaders = result?.headers || [];
    const routing = result?.routing || [];
    const threats = result?.threats || [];




    // Compute overall authentication grade


    return (
        <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
            {/* Page Header */}
            <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div className="page-header-icon" style={{ background: 'hsla(var(--color-primary), 0.1)', color: 'hsl(var(--color-primary))' }}>
                        <Mail size={28} />
                    </div>
                    <div>
                        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Email Header Analyzer</h1>
                        <p style={{ color: 'hsl(var(--text-secondary))', margin: 0, fontSize: '0.9rem' }}>Parse email headers to trace origin, verify authentication &amp; detect spoofing</p>
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
                                    <ScanHistoryTable type="EMAIL" onDelete={() => {}} />
                                </div>
                            </div>
                        </>
                    )}
                </div>
            </div>

            {/* Input Card */}
            <Card style={{ marginBottom: '1.5rem' }}>
                <div style={{ marginBottom: '1rem' }}>
                    <label style={{ 
                        display: 'block', marginBottom: '0.5rem', fontWeight: 600,
                        color: 'hsl(var(--text-secondary))', fontSize: '0.875rem'
                    }}>
                        Paste Email Headers
                    </label>
                    <textarea
                        value={headers}
                        onChange={(e) => setHeaders(e.target.value)}
                        placeholder={"Paste the full email headers here...\n\n(In most email clients: View > Message Source or Show Original)"}
                        style={{
                            width: '100%', minHeight: '180px', padding: '1rem',
                            borderRadius: 'var(--radius-lg)',
                            border: '1px solid hsl(var(--border-color))',
                            background: 'hsl(var(--bg-input))',
                            color: 'hsl(var(--text-primary))',
                            fontFamily: 'monospace', fontSize: '0.8rem', resize: 'vertical'
                        }}
                    />
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
                    <Button onClick={() => { setHeaders(''); setResult(null); }} variant="secondary">
                        <RefreshCw size={16} />
                        Clear
                    </Button>
                    <Button onClick={parseHeaders} isLoading={loading} variant="primary">
                        <Zap size={16} />
                        Analyze Headers
                    </Button>
                </div>
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
                    <AlertTriangle size={20} />
                    {error}
                </div>
            )}

            {/* Results */}
            {summary && result && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    {/* Actions Bar */}
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                        <ExportButton 
                            getPDFData={() => {
                                const tables: { title: string; headers: string[]; rows: (string | number)[][] }[] = [];

                                // Table 1: Authentication Results
                                tables.push({
                                    title: 'Authentication Results',
                                    headers: ['Check', 'Status', 'Details'],
                                    rows: [
                                        ['SPF (Sender Policy Framework)', summary.spf || 'Not Found', summary.spf_detail || '-'],
                                        ['DKIM (DomainKeys Identified Mail)', summary.dkim || 'Not Found', summary.dkim_detail || '-'],
                                        ['DMARC (Domain-based Auth)', summary.dmarc || 'Not Found', summary.dmarc_detail || '-'],
                                    ]
                                });

                                // Table 2: Routing Trace
                                if (routing.length > 0) {
                                    tables.push({
                                        title: `Routing Trace (${routing.length} Hops)`,
                                        headers: ['Hop', 'From', 'To', 'IP', 'Protocol', 'TLS', 'Delay', 'Timestamp'],
                                        rows: routing.map((hop: any) => [
                                            hop.hop,
                                            hop.from_host || '-',
                                            hop.by_host || '-',
                                            hop.ip || '-',
                                            hop.protocol || '-',
                                            hop.tls ? 'Yes' : 'No',
                                            hop.delay_seconds != null ? `${hop.delay_seconds}s` : '-',
                                            hop.timestamp || '-'
                                        ])
                                    });
                                }

                                // Table 3: Threat Indicators
                                if (threats.length > 0) {
                                    tables.push({
                                        title: `Threat Indicators (${threats.length})`,
                                        headers: ['Type', 'Severity', 'Description'],
                                        rows: threats.map((t: any) => [
                                            t.type.replace(/_/g, ' '),
                                            t.severity.toUpperCase(),
                                            t.description
                                        ])
                                    });
                                }

                                // Table 4: All Parsed Headers
                                if (parsedHeaders.length > 0) {
                                    tables.push({
                                        title: `All Parsed Headers (${parsedHeaders.length})`,
                                        headers: ['Status', 'Category', 'Header', 'Value', 'Analysis'],
                                        rows: parsedHeaders.map((h: any) => [
                                            (h.status || 'info').toUpperCase(),
                                            (h.category || 'general').toUpperCase(),
                                            h.key,
                                            h.value.substring(0, 120) + (h.value.length > 120 ? '...' : ''),
                                            h.analysis || '-'
                                        ])
                                    });
                                }

                                return {
                                    title: 'Email Header Analysis Report',
                                    subtitle: `Trust Grade: ${summary.trust_grade || '?'} (${summary.trust_score ?? '?'}/100)`,
                                    summary: {
                                        'From': summary.from || 'Unknown',
                                        'To': summary.to || 'Unknown',
                                        'Subject': summary.subject || 'N/A',
                                        'Date': summary.date || 'Unknown',
                                        'Trust Score': `${summary.trust_score ?? '?'}/100 (Grade ${summary.trust_grade || '?'})`,
                                        'SPF': summary.spf || 'Not Found',
                                        'DKIM': summary.dkim || 'Not Found',
                                        'DMARC': summary.dmarc || 'Not Found',
                                        'Server Hops': summary.hops || 0,
                                        'Total Delivery Time': summary.total_delay_seconds ? `${Math.round(summary.total_delay_seconds)}s` : 'N/A',
                                        'Total Headers': result.total_headers || parsedHeaders.length,
                                        'Threats Detected': threats.length,
                                        'Return-Path': summary.return_path || 'N/A',
                                        'Message-ID': summary.message_id || 'N/A',
                                        'Scan Date': new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
                                    },
                                    tables,
                                    flags: [
                                        ...threats.map((t: any) => `[${t.severity.toUpperCase()}] ${t.type.replace(/_/g, ' ')}: ${t.description}`),
                                        ...parsedHeaders
                                            .filter((h: any) => h.status === 'danger')
                                            .map((h: any) => `[DANGER] ${h.key}: ${h.analysis || h.value}`)
                                    ]
                                };
                            }}
                            getJSONData={() => result}
                        />
                        <Button onClick={() => { setHeaders(''); setResult(null); }} variant="secondary" size="sm">
                            <RefreshCw size={16} />
                            New Analysis
                        </Button>
                    </div>

                    <ScanResultViewer 
                        scanType="EMAIL_HEADERS" 
                        target="Email Headers" 
                        result={result} 
                        createdAt={new Date().toISOString()}
                    />
                </div>
            )}


        </div>
    );
};
