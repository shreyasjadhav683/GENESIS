
import { useState } from 'react';
import { Card } from '../../components/Card';
import { Button } from '../../components/Button';
import { 
    Puzzle, AlertTriangle, ShieldCheck, ShieldAlert, 
    ChevronDown, ChevronUp, RefreshCw, Zap,
    AlertCircle, CheckCircle, Trash2, History
} from 'lucide-react';
import { api } from '../../services/api';
import { ScanHistoryTable } from '../../components/ScanHistoryTable';
import { ExportButton } from '../../components/ExportButton';
import { generateExtensionScanReport } from '../../utils/reportGenerators';

interface RiskFactor {
    permission: string;
    risk: string;
    description: string;
}

interface Remediation {
    action: 'REMOVE' | 'REVIEW' | 'KEEP';
    description: string;
    steps: string[];
}

interface Extension {
    id: string;
    name: string;
    version: string;
    description: string;
    browser: string;
    manifest_version: number;
    permissions: string[];
    host_permissions: string[];
    risk_level: string;
    risk_score: number;
    risk_factors: RiskFactor[];
    author?: string;
    homepage_url?: string;
    remediation?: Remediation;
}

interface ScanResult {
    extensions: Extension[];
    summary: {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        browsers_scanned: string[];
    };
    scan_time: string;
}

const getRiskColor = (level: string) => {
    switch (level) {
        case 'CRITICAL': return 'hsl(0, 85%, 50%)';
        case 'HIGH': return '#f97316';
        case 'MEDIUM': return 'hsl(var(--color-warning))';
        default: return 'hsl(var(--color-success))';
    }
};

const getRiskBg = (level: string) => {
    switch (level) {
        case 'CRITICAL': return 'hsla(0, 85%, 50%, 0.08)';
        case 'HIGH': return 'hsla(30, 100%, 50%, 0.08)';
        case 'MEDIUM': return 'hsla(var(--color-warning), 0.08)';
        default: return 'hsla(var(--color-success), 0.08)';
    }
};

export const BrowserExtensionScanner = () => {
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<ScanResult | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [expandedExt, setExpandedExt] = useState<string | null>(null);
    const [showHistory, setShowHistory] = useState(false);

    const handleScan = async () => {
        setLoading(true);
        setError(null);
        setResult(null);

        try {
            const response = await api.get('/scan/browser-extensions');
            const sanitizedResult = response.data;
            if (sanitizedResult && Array.isArray(sanitizedResult.extensions)) {
                sanitizedResult.extensions = sanitizedResult.extensions.map((ext: any) => ({
                    ...ext,
                    permissions: (Array.isArray(ext.permissions) ? ext.permissions : []).map((p: any) => 
                        typeof p === 'string' ? p : JSON.stringify(p)
                    ),
                    host_permissions: (Array.isArray(ext.host_permissions) ? ext.host_permissions : []).map((p: any) => 
                        typeof p === 'string' ? p : JSON.stringify(p)
                    ),
                    risk_factors: (Array.isArray(ext.risk_factors) ? ext.risk_factors : []).map((f: any) => ({
                        ...f,
                        permission: typeof f.permission === 'string' ? f.permission : JSON.stringify(f.permission),
                        description: typeof f.description === 'string' ? f.description : JSON.stringify(f.description)
                    }))
                }));
            }
            setResult(sanitizedResult);
        } catch (err: any) {
            setError(err.response?.data?.detail || err.message || 'Failed to scan extensions');
        } finally {
            setLoading(false);
        }
    };

    const getOverallGrade = () => {
        if (!result?.summary) return { grade: '?', color: 'hsl(var(--text-muted))' };
        const { critical, high, medium, total } = result.summary;
        if (critical > 0) return { grade: 'F', color: 'hsl(0, 85%, 50%)' };
        if (high > 0) return { grade: 'D', color: '#f97316' };
        if (medium > 2) return { grade: 'C', color: 'hsl(var(--color-warning))' };
        if (medium > 0) return { grade: 'B', color: 'hsl(var(--color-success))' };
        if (total === 0) return { grade: '—', color: 'hsl(var(--text-muted))' };
        return { grade: 'A', color: 'hsl(var(--color-success))' };
    };

    const overallGrade = getOverallGrade();

    return (
        <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
            {/* Page Header */}
            <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div className="page-header-icon" style={{ background: 'hsla(270, 100%, 60%, 0.1)', color: '#a855f7' }}>
                        <Puzzle size={28} />
                    </div>
                    <div>
                        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Browser Extension Scanner</h1>
                        <p style={{ color: 'hsl(var(--text-secondary))', margin: 0, fontSize: '0.9rem' }}>Scan installed extensions for security risks &amp; malicious permissions</p>
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
                                    <ScanHistoryTable type="BROWSER_EXTENSIONS" onDelete={() => {}} />
                                </div>
                            </div>
                        </>
                    )}
                </div>
            </div>

            {/* Scan Card */}
            <Card style={{ marginBottom: '1.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
                    <div>
                        <h3 style={{ fontSize: '1.125rem', fontWeight: 700, marginBottom: '0.5rem' }}>
                            Extension Security Analysis
                        </h3>
                        <p style={{ color: 'hsl(var(--text-secondary))', fontSize: '0.875rem' }}>
                            Scans Chrome, Edge, Brave, and Firefox extensions on this machine
                        </p>
                    </div>
                    <Button onClick={handleScan} isLoading={loading} variant="primary">
                        <Zap size={18} />
                        Scan Extensions
                    </Button>
                </div>
            </Card>

            {/* Error */}
            {error && (
                <div style={{ 
                    padding: '1rem', background: 'hsl(var(--color-error-light))', 
                    border: '1px solid hsla(var(--color-error), 0.3)', 
                    borderRadius: 'var(--radius-lg)', color: 'hsl(var(--color-error))', fontWeight: 600,
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
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                            {(result.summary?.critical || 0) === 0 && (result.summary?.high || 0) === 0 ?
                                <ShieldCheck size={24} style={{ color: 'hsl(var(--color-success))' }} /> :
                                <ShieldAlert size={24} style={{ color: 'hsl(var(--color-error))' }} />
                            }
                            <span style={{ fontWeight: 700, color: (result.summary?.critical || 0) === 0 && (result.summary?.high || 0) === 0 ? 'hsl(var(--color-success))' : 'hsl(var(--color-error))' }}>
                                {(result.summary?.critical || 0) + (result.summary?.high || 0) > 0 
                                    ? `${(result.summary?.critical || 0) + (result.summary?.high || 0)} Risky Extension${(result.summary?.critical || 0) + (result.summary?.high || 0) > 1 ? 's' : ''} Found` 
                                    : 'Extensions Appear Safe'}
                            </span>
                        </div>
                        <div style={{ display: 'flex', gap: '0.5rem' }}>
                            <ExportButton 
                                getPDFData={() => generateExtensionScanReport(result)}
                                getJSONData={() => result}
                            />
                            <Button onClick={() => setResult(null)} variant="secondary" size="sm">
                                <RefreshCw size={16} />
                                New Scan
                            </Button>
                        </div>
                    </div>

                    {/* ROW 1: Grade + Summary Stats */}
                    <div style={{ display: 'grid', gridTemplateColumns: '160px 1fr', gap: '1.5rem' }}>
                        {/* Overall Grade */}
                        <Card>
                            <div style={{ textAlign: 'center', padding: '0.75rem 0' }}>
                                <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>
                                    Security
                                </p>
                                <p style={{ fontSize: '3.5rem', fontWeight: 900, lineHeight: 1, color: overallGrade.color }}>
                                    {overallGrade.grade}
                                </p>
                                <p style={{ marginTop: '0.5rem', fontSize: '0.7rem', color: 'hsl(var(--text-muted))' }}>
                                    {result.summary?.total || 0} extension{(result.summary?.total || 0) !== 1 ? 's' : ''}
                                </p>
                            </div>
                        </Card>

                        {/* Summary Stats Grid */}
                        <Card>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '0.5rem' }}>
                                {[
                                    { label: 'Total', value: result.summary?.total || 0, color: 'hsl(var(--color-primary))' },
                                    { label: 'Critical', value: result.summary?.critical || 0, color: getRiskColor('CRITICAL') },
                                    { label: 'High', value: result.summary?.high || 0, color: getRiskColor('HIGH') },
                                    { label: 'Medium', value: result.summary?.medium || 0, color: getRiskColor('MEDIUM') },
                                    { label: 'Low', value: result.summary?.low || 0, color: getRiskColor('LOW') },
                                ].map((stat) => (
                                    <div key={stat.label} style={{
                                        padding: '0.75rem',
                                        background: stat.value > 0 && stat.label !== 'Total' && stat.label !== 'Low' ? `${stat.color}08` : 'hsl(var(--bg-secondary))',
                                        borderRadius: 'var(--radius-md)',
                                        textAlign: 'center',
                                        border: stat.value > 0 && (stat.label === 'Critical' || stat.label === 'High') ? `1px solid ${stat.color}25` : '1px solid transparent'
                                    }}>
                                        <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase', marginBottom: '0.25rem' }}>{stat.label}</p>
                                        <p style={{ fontSize: '1.75rem', fontWeight: 900, color: stat.color }}>{stat.value}</p>
                                    </div>
                                ))}
                            </div>
                            {/* Risk distribution bar */}
                            {(result.summary?.total || 0) > 0 && (
                                <div style={{ 
                                    marginTop: '0.75rem', height: '6px', borderRadius: '3px',
                                    display: 'flex', overflow: 'hidden', background: 'hsl(var(--bg-secondary))'
                                }}>
                                    {[
                                        { count: result.summary?.critical || 0, color: getRiskColor('CRITICAL') },
                                        { count: result.summary?.high || 0, color: getRiskColor('HIGH') },
                                        { count: result.summary?.medium || 0, color: getRiskColor('MEDIUM') },
                                        { count: result.summary?.low || 0, color: getRiskColor('LOW') },
                                    ].filter(s => s.count > 0).map((s, i) => (
                                        <div key={i} style={{
                                            width: `${(s.count / (result.summary?.total || 1)) * 100}%`,
                                            background: s.color, height: '100%'
                                        }} />
                                    ))}
                                </div>
                            )}
                        </Card>
                    </div>

                    {/* Browser Distribution Graph */}
                    <Card title="Extensions by Browser Profile">
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                            {(() => {
                                const browserCounts: Record<string, number> = {};
                                result.extensions.forEach(ext => {
                                    browserCounts[ext.browser] = (browserCounts[ext.browser] || 0) + 1;
                                });
                                
                                const sortedBrowsers = Object.entries(browserCounts)
                                    .sort(([, a], [, b]) => b - a);
                                
                                const maxCount = Math.max(...Object.values(browserCounts), 1);
                                const colors = [
                                    'hsl(var(--color-primary))', '#3b82f6', '#10b981', '#f59e0b', '#ec4899', '#8b5cf6'
                                ];

                                return sortedBrowsers.map(([browser, count], idx) => (
                                    <div key={browser} style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                                        <div style={{ width: '140px', textAlign: 'right', fontSize: '0.85rem', color: 'hsl(var(--text-secondary))', fontWeight: 600 }}>
                                            {browser}
                                        </div>
                                        <div style={{ flex: 1, height: '24px', background: 'hsl(var(--bg-secondary))', borderRadius: '4px', overflow: 'hidden', position: 'relative' }}>
                                            <div style={{ 
                                                width: `${(count / maxCount) * 100}%`, 
                                                height: '100%', 
                                                background: colors[idx % colors.length],
                                                borderRadius: '4px',
                                                display: 'flex', alignItems: 'center', justifyContent: 'flex-end', paddingRight: '0.5rem',
                                                transition: 'width 1s ease-out'
                                            }}>
                                                <span style={{ color: '#000', fontWeight: 700, fontSize: '0.75rem' }}>{count}</span>
                                            </div>
                                        </div>
                                    </div>
                                ));
                            })()}
                        </div>
                    </Card>

                    {/* Remediation Alert */}
                    {((result.summary?.critical || 0) > 0 || (result.summary?.high || 0) > 0) && (
                        <div style={{
                            padding: '1.25rem 1.5rem',
                            background: 'hsl(var(--bg-card))',
                            border: '1px solid hsla(var(--color-error), 0.4)',
                            borderRadius: 'var(--radius-lg)',
                            borderLeft: '4px solid hsl(var(--color-error))'
                        }}>
                            <h3 style={{ 
                                display: 'flex', alignItems: 'center', gap: '0.75rem', 
                                color: 'hsl(var(--color-error))', fontSize: '1rem', marginBottom: '0.75rem'
                            }}>
                                <AlertCircle size={22} />
                                Immediate Action Required
                            </h3>
                            <p style={{ marginBottom: '0.75rem', color: 'hsl(var(--text-secondary))', fontSize: '0.875rem' }}>
                                <strong>{(result.summary?.critical || 0) + (result.summary?.high || 0)} extension{(result.summary?.critical || 0) + (result.summary?.high || 0) > 1 ? 's' : ''}</strong> contain critical security risks. Remove them immediately via your browser's extension manager.
                            </p>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                                {result.extensions
                                    .filter(e => e.risk_level === 'CRITICAL' || e.risk_level === 'HIGH')
                                    .map((e, idx) => (
                                        <span key={`${e.id}-${idx}`} style={{
                                            padding: '0.25rem 0.6rem', borderRadius: 'var(--radius-full)',
                                            fontSize: '0.75rem', fontWeight: 700,
                                            background: getRiskBg(e.risk_level),
                                            color: getRiskColor(e.risk_level),
                                            border: `1px solid ${getRiskColor(e.risk_level)}25`
                                        }}>
                                            {e.name} ({e.browser})
                                        </span>
                                    ))
                                }
                            </div>
                        </div>
                    )}

                    {/* Extensions List */}
                    <Card title={`Extensions (${(result.extensions || []).length})`}>
                        {(result.extensions || []).length === 0 ? (
                            <div style={{ padding: '2rem', textAlign: 'center', color: 'hsl(var(--text-muted))' }}>
                                <Puzzle size={48} style={{ opacity: 0.3, marginBottom: '1rem' }} />
                                <p>No browser extensions found on this machine</p>
                            </div>
                        ) : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                                {(result.extensions || []).map((ext, idx) => {
                                    if (!ext) return null;
                                    const riskFactors = Array.isArray(ext.risk_factors) ? ext.risk_factors : [];
                                    const rawRemediation = (typeof ext.remediation === 'object' && ext.remediation !== null) ? ext.remediation : {} as any;
                                    
                                    const getDefaultRemediation = (level: string) => {
                                        switch (level) {
                                            case 'CRITICAL':
                                            case 'HIGH':
                                                return {
                                                    action: 'REMOVE',
                                                    description: 'This extension poses a significant security risk. Immediate removal is recommended.',
                                                    steps: [
                                                        'Open your browser\'s extension manager (chrome://extensions or about:addons)',
                                                        `Locate "${ext.name}" in the list`,
                                                        'Click the "Remove" or "Uninstall" button',
                                                        'Restart your browser'
                                                    ]
                                                };
                                            case 'MEDIUM':
                                                return {
                                                    action: 'REVIEW',
                                                    description: 'This extension has permissions that could be misused. Review its necessity.',
                                                    steps: [
                                                        'Check if you recognize and use this extension',
                                                        'Review the permissions listed below',
                                                        'If unused or suspicious, remove it via your browser settings'
                                                    ]
                                                };
                                            default:
                                                return { action: 'KEEP', description: 'This extension appears safe but should be kept up to date.', steps: [] };
                                        }
                                    };

                                    const defaults = getDefaultRemediation(ext.risk_level);
                                    const remediation = { 
                                        action: rawRemediation.action || defaults.action, 
                                        description: rawRemediation.description || defaults.description, 
                                        steps: (rawRemediation.action === 'REMOVE' && Array.isArray(rawRemediation.steps) && rawRemediation.steps.length > 0) 
                                            ? rawRemediation.steps : defaults.steps 
                                    };
                                    const uniqueId = `${ext.id}-${idx}`;
                                    const isExpanded = expandedExt === uniqueId;
                                    const isExpandable = ext.risk_level === 'CRITICAL' || ext.risk_level === 'HIGH';
                                    
                                    return (
                                    <div key={uniqueId} style={{ 
                                        border: `1px solid ${isExpanded ? getRiskColor(ext.risk_level) + '40' : 'hsl(var(--border-color))'}`,
                                        borderRadius: 'var(--radius-lg)',
                                        overflow: 'hidden',
                                        transition: 'border-color 0.2s'
                                    }}>
                                        {/* Extension Header */}
                                        <div 
                                            onClick={() => isExpandable && setExpandedExt(isExpanded ? null : uniqueId)}
                                            style={{ 
                                                padding: '0.75rem 1rem',
                                                display: 'flex', alignItems: 'center',
                                                justifyContent: 'space-between',
                                                cursor: isExpandable ? 'pointer' : 'default',
                                                background: isExpanded ? getRiskBg(ext.risk_level) : 'hsl(var(--bg-secondary))',
                                                transition: 'background 0.2s'
                                            }}
                                        >
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: 1, minWidth: 0 }}>
                                                <div style={{ 
                                                    padding: '0.4rem', borderRadius: 'var(--radius-md)',
                                                    background: getRiskBg(ext.risk_level)
                                                }}>
                                                    {ext.risk_level === 'CRITICAL' || ext.risk_level === 'HIGH' ? 
                                                        <ShieldAlert size={18} style={{ color: getRiskColor(ext.risk_level) }} /> :
                                                        <ShieldCheck size={18} style={{ color: getRiskColor(ext.risk_level) }} />
                                                    }
                                                </div>
                                                <div style={{ flex: 1, minWidth: 0 }}>
                                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                                                        <span style={{ fontWeight: 700, fontSize: '0.9rem' }}>{ext.name}</span>
                                                        <span style={{ 
                                                            fontSize: '0.6rem', padding: '0.1rem 0.4rem',
                                                            background: 'hsl(var(--bg-tertiary))',
                                                            borderRadius: 'var(--radius-full)', color: 'hsl(var(--text-muted))'
                                                        }}>v{ext.version}</span>
                                                        <span style={{ 
                                                            fontSize: '0.6rem', padding: '0.1rem 0.4rem',
                                                            background: 'hsla(var(--color-info), 0.1)',
                                                            borderRadius: 'var(--radius-full)', color: 'hsl(var(--color-info))'
                                                        }}>{ext.browser}</span>
                                                    </div>
                                                    <p style={{ 
                                                        fontSize: '0.75rem', color: 'hsl(var(--text-secondary))',
                                                        marginTop: '0.15rem', whiteSpace: 'nowrap',
                                                        overflow: 'hidden', textOverflow: 'ellipsis'
                                                    }}>
                                                        {ext.description || 'No description'}
                                                    </p>
                                                </div>
                                            </div>
                                            
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                                <span style={{ 
                                                    padding: '0.2rem 0.6rem', borderRadius: 'var(--radius-full)',
                                                    background: getRiskBg(ext.risk_level),
                                                    color: getRiskColor(ext.risk_level),
                                                    fontWeight: 700, fontSize: '0.7rem'
                                                }}>
                                                    {ext.risk_level} ({ext.risk_score})
                                                </span>
                                                {isExpandable && (isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />)}
                                            </div>
                                        </div>
                                        
                                        {/* Expanded Details */}
                                        {isExpanded && (
                                            <div style={{ padding: '1rem', borderTop: '1px solid hsl(var(--border-color))' }}>
                                                {/* Remediation */}
                                                <div style={{ 
                                                    padding: '0.75rem 1rem', 
                                                    background: remediation.action === 'REMOVE' ? 'hsla(var(--color-error), 0.08)' : 
                                                               remediation.action === 'REVIEW' ? 'hsla(var(--color-warning), 0.08)' : 'hsla(var(--color-success), 0.08)',
                                                    borderRadius: 'var(--radius-md)', marginBottom: '1rem',
                                                    borderLeft: `3px solid ${
                                                        remediation.action === 'REMOVE' ? 'hsl(var(--color-error))' : 
                                                        remediation.action === 'REVIEW' ? 'hsl(var(--color-warning))' : 'hsl(var(--color-success))'
                                                    }`
                                                }}>
                                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                                                        {remediation.action === 'REMOVE' ? <Trash2 size={16} style={{ color: 'hsl(var(--color-error))' }} /> : 
                                                         remediation.action === 'REVIEW' ? <AlertTriangle size={16} style={{ color: 'hsl(var(--color-warning))' }} /> :
                                                         <CheckCircle size={16} style={{ color: 'hsl(var(--color-success))' }} />}
                                                        <span style={{ fontWeight: 700, fontSize: '0.85rem' }}>
                                                            Action: <span style={{ 
                                                                color: remediation.action === 'REMOVE' ? 'hsl(var(--color-error))' : 
                                                                       remediation.action === 'REVIEW' ? 'hsl(var(--color-warning))' : 'hsl(var(--color-success))'
                                                            }}>{remediation.action}</span>
                                                        </span>
                                                    </div>
                                                    <p style={{ fontSize: '0.8rem', color: 'hsl(var(--text-secondary))' }}>{remediation.description}</p>
                                                    {remediation.action !== 'KEEP' && remediation.steps && remediation.steps.length > 0 && (
                                                        <ol style={{ paddingLeft: '1.25rem', fontSize: '0.8rem', color: 'hsl(var(--text-secondary))', marginTop: '0.5rem' }}>
                                                            {remediation.steps.map((step: string, sIdx: number) => (
                                                                <li key={sIdx} style={{ marginBottom: '0.15rem' }}>{step}</li>
                                                            ))}
                                                        </ol>
                                                    )}
                                                </div>

                                                {/* Metadata */}
                                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.5rem', marginBottom: '1rem' }}>
                                                    <div style={{ padding: '0.4rem 0.6rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                                                        <span style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>ID</span>
                                                        <p style={{ fontSize: '0.72rem', fontFamily: 'monospace', wordBreak: 'break-all' }}>{ext.id}</p>
                                                    </div>
                                                    {ext.author && (
                                                        <div style={{ padding: '0.4rem 0.6rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                                                            <span style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Author</span>
                                                            <p style={{ fontSize: '0.8rem' }}>{ext.author}</p>
                                                        </div>
                                                    )}
                                                    <div style={{ padding: '0.4rem 0.6rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                                                        <span style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Manifest</span>
                                                        <p style={{ fontSize: '0.8rem' }}>v{ext.manifest_version}</p>
                                                    </div>
                                                </div>
                                                
                                                {/* Risk Factors */}
                                                {riskFactors.length > 0 && (
                                                    <div style={{ marginBottom: '1rem' }}>
                                                        <h4 style={{ fontSize: '0.75rem', fontWeight: 700, marginBottom: '0.4rem', textTransform: 'uppercase', color: 'hsl(var(--text-muted))' }}>
                                                            Risk Factors ({riskFactors.length})
                                                        </h4>
                                                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                                                            {riskFactors.filter(Boolean).map((factor, fIdx) => (
                                                                <div key={fIdx} style={{ 
                                                                    padding: '0.4rem 0.6rem',
                                                                    background: getRiskBg(factor.risk),
                                                                    borderRadius: 'var(--radius-sm)',
                                                                    display: 'flex', alignItems: 'center', gap: '0.5rem',
                                                                    border: `1px solid ${getRiskColor(factor.risk)}15`
                                                                }}>
                                                                    <span style={{ 
                                                                        padding: '0.1rem 0.35rem', borderRadius: 'var(--radius-sm)',
                                                                        background: getRiskColor(factor.risk), color: 'white',
                                                                        fontSize: '0.55rem', fontWeight: 700
                                                                    }}>{factor.risk}</span>
                                                                    <code style={{ fontSize: '0.72rem', color: 'hsl(var(--text-primary))' }}>{factor.permission}</code>
                                                                    <span style={{ fontSize: '0.72rem', color: 'hsl(var(--text-secondary))' }}>— {factor.description}</span>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </div>
                                                )}
                                                
                                                {/* All Permissions */}
                                                <div>
                                                    <h4 style={{ fontSize: '0.75rem', fontWeight: 700, marginBottom: '0.4rem', textTransform: 'uppercase', color: 'hsl(var(--text-muted))' }}>
                                                        All Permissions ({(ext.permissions || []).length + (ext.host_permissions || []).length})
                                                    </h4>
                                                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.2rem' }}>
                                                        {[...(ext.permissions || []), ...(ext.host_permissions || [])].map((perm, pIdx) => (
                                                            <span key={pIdx} style={{ 
                                                                padding: '0.2rem 0.4rem',
                                                                background: 'hsl(var(--bg-tertiary))',
                                                                borderRadius: 'var(--radius-sm)',
                                                                fontSize: '0.65rem', fontFamily: 'monospace'
                                                            }}>{perm}</span>
                                                        ))}
                                                        {(ext.permissions || []).length + (ext.host_permissions || []).length === 0 && (
                                                            <span style={{ fontSize: '0.8rem', color: 'hsl(var(--text-muted))' }}>No permissions declared</span>
                                                        )}
                                                    </div>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                    );
                                })}
                            </div>
                        )}
                    </Card>
                </div>
            )}


        </div>
    );
};
