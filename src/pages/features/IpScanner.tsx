
import React, { useState } from 'react';
import { Card } from '../../components/Card';
import { Input } from '../../components/Input';
import { Button } from '../../components/Button';
import { api } from '../../services/api';
import { ScanHistoryTable } from '../../components/ScanHistoryTable';
import { ExportButton } from '../../components/ExportButton';
import { 
    Search, Globe, ShieldAlert, ShieldCheck, RefreshCw,
    AlertTriangle, Zap, Activity, Info, MapPin, Server, Wifi, History
} from 'lucide-react';

interface RiskFactor {
    name: string;
    impact: number;
    description: string;
}

interface ScanResult {
    ip: string;
    geolocation: any;
    network_info: any;
    geographic_details: any;
    threat_intelligence: any;
    abuse_history: any;
    port_scan: any;
    dns_info: any;
    risk_assessment: {
        score: number;
        severity: string;
        factors: RiskFactor[];
        recommendation: string;
        is_malicious: boolean;
    };
    scan_timestamp: string;
}

const getSeverityColor = (severity: string) => {
    switch (severity) {
        case 'Critical': return 'hsl(var(--color-error))';
        case 'High': return '#f97316';
        case 'Medium': return 'hsl(var(--color-warning))';
        default: return 'hsl(var(--color-success))';
    }
};

const getRiskColor = (score: number) => {
    if (score >= 70) return 'hsl(var(--color-error))';
    if (score >= 40) return 'hsl(var(--color-warning))';
    if (score >= 15) return 'hsl(var(--color-info))';
    return 'hsl(var(--color-success))';
};

const severityStyles: Record<string, { bg: string; color: string; border: string; icon: React.ReactNode }> = {
    critical: { 
        bg: 'hsla(0, 85%, 50%, 0.08)', color: 'hsl(0, 85%, 50%)', 
        border: 'hsla(0, 85%, 50%, 0.25)', icon: <ShieldAlert size={16} />
    },
    high: { 
        bg: 'hsla(15, 90%, 55%, 0.08)', color: 'hsl(15, 90%, 55%)', 
        border: 'hsla(15, 90%, 55%, 0.25)', icon: <AlertTriangle size={16} />
    },
    medium: { 
        bg: 'hsla(40, 90%, 50%, 0.08)', color: 'hsl(40, 90%, 50%)', 
        border: 'hsla(40, 90%, 50%, 0.25)', icon: <Info size={16} />
    },
    low: { 
        bg: 'hsla(210, 60%, 50%, 0.08)', color: 'hsl(210, 60%, 50%)', 
        border: 'hsla(210, 60%, 50%, 0.25)', icon: <Activity size={16} />
    }
};

const getFactorSeverity = (impact: number) => {
    if (impact >= 25) return 'critical';
    if (impact >= 15) return 'high';
    if (impact >= 8) return 'medium';
    return 'low';
};

export const IpScanner = () => {
    const [ip, setIp] = useState('');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<ScanResult | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [showHistory, setShowHistory] = useState(false);

    const handleScan = async (e: React.FormEvent) => {
        e.preventDefault();
        const trimmedIp = ip.trim();
        if (!trimmedIp) return;
        
        setLoading(true);
        setError(null);
        setResult(null);

        try {
            const response = await api.post(`/ip/scan?ip_address=${encodeURIComponent(trimmedIp)}`);
            setResult(response.data);
        } catch (err: any) {
            setError(err.response?.data?.detail || err.message || "Scan failed");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
            {/* Page Header */}
            <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div className="page-header-icon" style={{ background: 'hsla(var(--color-primary), 0.1)', color: 'hsl(var(--color-primary))' }}>
                        <Globe size={28} />
                    </div>
                    <div>
                        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>IP Scanner</h1>
                        <p style={{ color: 'hsl(var(--text-secondary))', margin: 0, fontSize: '0.9rem' }}>Advanced threat intelligence & risk analysis</p>
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
                                    <ScanHistoryTable type="IP" onDelete={() => {}} />
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
                            label="Target IP Address" 
                            placeholder="Enter IP address (e.g., 8.8.8.8)" 
                            value={ip}
                            onChange={(e) => setIp(e.target.value)}
                            icon={<Search size={18} />}
                            required
                        />
                    </div>
                    <Button type="submit" isLoading={loading} variant="primary">
                        <Zap size={18} />
                        {loading ? 'Analyzing...' : 'Deep Scan'}
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
                    
                    {/* Action Buttons */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                            {result.risk_assessment.is_malicious ? 
                                <ShieldAlert size={24} style={{ color: 'hsl(var(--color-error))' }} /> :
                                <ShieldCheck size={24} style={{ color: 'hsl(var(--color-success))' }} />
                            }
                            <span style={{ 
                                fontWeight: 700, 
                                color: result.risk_assessment.is_malicious ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))'
                            }}>
                                {result.risk_assessment.is_malicious ? 'Potential Threat Detected' : 'No Threats Detected'}
                            </span>
                        </div>
                        <div style={{ display: 'flex', gap: '0.75rem' }}>
                            <ExportButton 
                                getPDFData={() => {
                                    const riskAssessment = result.risk_assessment || {} as any;
                                    const threatIntel = result.threat_intelligence || {} as any;
                                    const networkInfo = result.network_info || {} as any;
                                    const geoDetails = result.geographic_details || {} as any;
                                    const abuseHistory = result.abuse_history || {} as any;
                                    const portScan = result.port_scan || {} as any;
                                    const dnsInfo = result.dns_info || {} as any;
                                    
                                    const indicators: string[] = [];
                                    if (threatIntel.is_proxy) indicators.push('Proxy');
                                    if (threatIntel.is_tor_exit) indicators.push('Tor Exit');
                                    if (threatIntel.is_vpn) indicators.push('VPN');
                                    if (threatIntel.is_blacklisted) indicators.push('BLACKLISTED');
                                    if (threatIntel.is_datacenter) indicators.push('Datacenter');
                                    
                                    const tables: Array<{ title: string; headers: string[]; rows: (string | number)[][] }> = [];
                                    
                                    if (riskAssessment.factors && riskAssessment.factors.length > 0) {
                                        tables.push({
                                            title: 'Risk Factors',
                                            headers: ['Factor', 'Impact', 'Description'],
                                            rows: riskAssessment.factors.map((f: any) => [f.name, `+${f.impact}`, f.description])
                                        });
                                    }
                                    
                                    tables.push({
                                        title: 'Network Details',
                                        headers: ['Property', 'Value'],
                                        rows: [
                                            ['IP Address', result.ip || ''],
                                            ['ISP', networkInfo.isp || 'N/A'],
                                            ['Organization', networkInfo.organization || 'N/A'],
                                            ['Domain', networkInfo.domain || 'N/A'],
                                            ['ASN', networkInfo.asn || 'N/A'],
                                            ['ASN Name', networkInfo.asn_name || 'N/A'],
                                            ['Network Range', networkInfo.network_range || 'N/A'],
                                            ['Reverse DNS', dnsInfo.reverse_dns || 'N/A'],
                                        ]
                                    });
                                    
                                    tables.push({
                                        title: 'Location & History',
                                        headers: ['Property', 'Value'],
                                        rows: [
                                            ['Country', `${geoDetails.country || 'N/A'} (${geoDetails.country_code || ''})`],
                                            ['Region', geoDetails.region_name || geoDetails.region || 'N/A'],
                                            ['City', geoDetails.city || 'N/A'],
                                            ['Timezone', geoDetails.timezone || 'N/A'],
                                            ['Coordinates', geoDetails.latitude && geoDetails.longitude ? `${geoDetails.latitude}, ${geoDetails.longitude}` : 'N/A'],
                                            ['Continent', geoDetails.continent || 'N/A'],
                                            ['Total Reports', String(abuseHistory.total_reports || 0)],
                                            ['Last Reported', abuseHistory.last_reported_at || threatIntel.last_reported || 'Never'],
                                        ]
                                    });
                                    
                                    if (portScan.open_ports && portScan.open_ports.length > 0) {
                                        tables.push({
                                            title: 'Port Scan Results',
                                            headers: ['Port', 'Service', 'Status'],
                                            rows: portScan.open_ports.map((port: number) => [
                                                String(port),
                                                portScan.services_detected?.[port] || 'Unknown',
                                                'OPEN'
                                            ])
                                        });
                                    }
                                    
                                    return {
                                        title: 'IP Scan Report',
                                        subtitle: result.ip,
                                        summary: {
                                            'Target': result.ip,
                                            'Scan Type': 'IP Scan',
                                            'Date': new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
                                            'Risk Score': `${riskAssessment.score || 0}/100`,
                                            'Severity': riskAssessment.severity || 'Unknown',
                                            'Verdict': riskAssessment.is_malicious ? 'MALICIOUS - BLOCK RECOMMENDED' : 'SAFE',
                                            'Recommendation': riskAssessment.recommendation || '',
                                            'Abuse Confidence': `${threatIntel.abuse_confidence_score || 0}%`,
                                            'Fraud Score': `${threatIntel.fraud_score || 0}%`,
                                            ...(indicators.length > 0 ? { 'Indicators': indicators.join(', ') } : {}),
                                        },
                                        tables,
                                        flags: []
                                    };
                                }}
                                getJSONData={() => result}
                            />
                            <Button onClick={() => { setResult(null); setIp(''); }} variant="secondary" size="sm">
                                <RefreshCw size={16} />
                                New Scan
                            </Button>
                        </div>
                    </div>

                    {/* ROW 1: Threat Grade + Risk Score + Summary Stats */}
                    <div style={{ display: 'grid', gridTemplateColumns: '200px 200px 1fr', gap: '1.5rem' }}>
                        {/* Threat Level */}
                        <Card>
                            <div style={{ textAlign: 'center', padding: '1rem 0' }}>
                                <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>
                                    Threat Level
                                </p>
                                <p style={{ 
                                    fontSize: '3.5rem', 
                                    fontWeight: 900, 
                                    color: result.risk_assessment.is_malicious ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))',
                                    lineHeight: 1
                                }}>
                                    {result.risk_assessment.is_malicious ? '⚠' : '✓'}
                                </p>
                                <p style={{ 
                                    marginTop: '0.5rem',
                                    padding: '0.25rem 0.75rem',
                                    borderRadius: 'var(--radius-full)',
                                    display: 'inline-block',
                                    fontSize: '0.75rem',
                                    fontWeight: 800,
                                    background: `${getSeverityColor(result.risk_assessment.severity)}15`,
                                    color: getSeverityColor(result.risk_assessment.severity)
                                }}>
                                    {result.risk_assessment.severity}
                                </p>
                            </div>
                        </Card>

                        {/* Risk Score */}
                        <Card>
                            <div style={{ textAlign: 'center', padding: '1rem 0' }}>
                                <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>
                                    Risk Score
                                </p>
                                <p style={{ 
                                    fontSize: '3rem', 
                                    fontWeight: 900, 
                                    color: getRiskColor(result.risk_assessment.score),
                                    lineHeight: 1
                                }}>
                                    {result.risk_assessment.score}
                                </p>
                                <div style={{ 
                                    marginTop: '0.75rem', 
                                    height: '6px', 
                                    borderRadius: '3px',
                                    background: 'hsl(var(--bg-secondary))',
                                    overflow: 'hidden'
                                }}>
                                    <div style={{ 
                                        height: '100%', 
                                        width: `${result.risk_assessment.score}%`,
                                        borderRadius: '3px',
                                        background: `linear-gradient(90deg, hsl(var(--color-success)), hsl(var(--color-warning)), hsl(var(--color-error)))`,
                                        transition: 'width 0.5s ease'
                                    }} />
                                </div>
                                <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', marginTop: '0.25rem' }}>out of 100</p>
                            </div>
                        </Card>

                        {/* Summary Stats */}
                        <Card>
                            <div style={{ padding: '0.25rem' }}>
                                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                                    <div style={{ padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                                        <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>IP Address</p>
                                        <p style={{ fontSize: '0.85rem', fontWeight: 700, fontFamily: 'monospace', color: 'hsl(var(--color-primary))' }}>{result.ip}</p>
                                    </div>
                                    <div style={{ padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                                        <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>ISP</p>
                                        <p style={{ fontSize: '0.8rem', fontWeight: 600 }}>{result.network_info?.isp || 'N/A'}</p>
                                    </div>
                                    <div style={{ padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                                        <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Location</p>
                                        <p style={{ fontSize: '0.8rem', fontWeight: 600 }}>{result.geographic_details?.city || '?'}, {result.geographic_details?.country || '?'}</p>
                                    </div>
                                    <div style={{ padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                                        <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>ASN</p>
                                        <p style={{ fontSize: '0.8rem', fontWeight: 600, fontFamily: 'monospace' }}>{result.network_info?.asn || 'N/A'}</p>
                                    </div>
                                </div>
                                {/* Indicators */}
                                <div style={{ marginTop: '0.5rem', display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                                    {result.threat_intelligence?.is_vpn && <span style={{ padding: '0.2rem 0.5rem', background: 'hsl(var(--color-error-light))', color: 'hsl(var(--color-error))', borderRadius: 'var(--radius-sm)', fontSize: '0.65rem', fontWeight: 700 }}>VPN</span>}
                                    {result.threat_intelligence?.is_proxy && <span style={{ padding: '0.2rem 0.5rem', background: 'hsla(30, 100%, 50%, 0.1)', color: '#f97316', borderRadius: 'var(--radius-sm)', fontSize: '0.65rem', fontWeight: 700 }}>Proxy</span>}
                                    {result.threat_intelligence?.is_tor_exit && <span style={{ padding: '0.2rem 0.5rem', background: 'hsl(var(--color-error-light))', color: 'hsl(var(--color-error))', borderRadius: 'var(--radius-sm)', fontSize: '0.65rem', fontWeight: 700 }}>Tor Exit</span>}
                                    {result.threat_intelligence?.is_bot && <span style={{ padding: '0.2rem 0.5rem', background: 'hsl(var(--color-warning-light))', color: 'hsl(var(--color-warning))', borderRadius: 'var(--radius-sm)', fontSize: '0.65rem', fontWeight: 700 }}>Bot</span>}
                                    {result.threat_intelligence?.is_datacenter && <span style={{ padding: '0.2rem 0.5rem', background: 'hsl(var(--color-info-light))', color: 'hsl(var(--color-info))', borderRadius: 'var(--radius-sm)', fontSize: '0.65rem', fontWeight: 700 }}>Datacenter</span>}
                                    {result.threat_intelligence?.is_mobile && <span style={{ padding: '0.2rem 0.5rem', background: 'hsla(var(--color-secondary), 0.1)', color: 'hsl(var(--color-secondary))', borderRadius: 'var(--radius-sm)', fontSize: '0.65rem', fontWeight: 700 }}>Mobile</span>}
                                    {result.threat_intelligence?.is_blacklisted && <span style={{ padding: '0.2rem 0.5rem', background: 'hsl(var(--color-error))', color: 'white', borderRadius: 'var(--radius-sm)', fontSize: '0.65rem', fontWeight: 800 }}>BLACKLISTED</span>}
                                    {result.abuse_history?.is_whitelisted && <span style={{ padding: '0.2rem 0.5rem', background: 'hsl(var(--color-success-light))', color: 'hsl(var(--color-success))', borderRadius: 'var(--radius-sm)', fontSize: '0.65rem', fontWeight: 700 }}>Whitelisted</span>}
                                </div>
                            </div>
                        </Card>
                    </div>

                    {/* ROW 2: Abuse & Fraud Scores */}
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                        <Card title="Abuse & Fraud Confidence">
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                                <div>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                                        <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>Abuse Confidence</span>
                                        <span style={{ fontWeight: 700, color: (result.threat_intelligence?.abuse_confidence_score || 0) > 50 ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))' }}>
                                            {result.threat_intelligence?.abuse_confidence_score || 0}%
                                        </span>
                                    </div>
                                    <div style={{ width: '100%', height: '8px', background: 'hsl(var(--bg-tertiary))', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
                                        <div style={{ 
                                            width: `${result.threat_intelligence?.abuse_confidence_score || 0}%`, 
                                            height: '100%', 
                                            background: (result.threat_intelligence?.abuse_confidence_score || 0) > 50 ? 'hsl(var(--color-error))' : 'hsl(var(--color-warning))',
                                            transition: 'width 0.5s ease'
                                        }} />
                                    </div>
                                </div>
                                <div>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                                        <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>Fraud Score</span>
                                        <span style={{ fontWeight: 700, color: (result.threat_intelligence?.fraud_score || 0) > 50 ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))' }}>
                                            {result.threat_intelligence?.fraud_score || 0}%
                                        </span>
                                    </div>
                                    <div style={{ width: '100%', height: '8px', background: 'hsl(var(--bg-tertiary))', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
                                        <div style={{ 
                                            width: `${result.threat_intelligence?.fraud_score || 0}%`, 
                                            height: '100%', 
                                            background: (result.threat_intelligence?.fraud_score || 0) > 50 ? 'hsl(var(--color-error))' : 'hsl(var(--color-warning))',
                                            transition: 'width 0.5s ease'
                                        }} />
                                    </div>
                                </div>
                                <div style={{ padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', marginTop: '0.25rem' }}>
                                    <p style={{ fontSize: '0.7rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Recommendation</p>
                                    <p style={{ fontSize: '0.8rem', fontWeight: 600 }}>{result.risk_assessment.recommendation}</p>
                                </div>
                            </div>
                        </Card>

                        {/* Connection Details */}
                        <Card title="Connection Details">
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                                {[
                                    { label: 'Usage Type', value: result.threat_intelligence?.usage_type || 'Unknown', icon: <Server size={14} /> },
                                    { label: 'Connection', value: result.threat_intelligence?.connection_type || 'Unknown', icon: <Wifi size={14} /> },
                                    { label: 'Reverse DNS', value: result.dns_info?.reverse_dns || 'N/A', icon: <Globe size={14} /> },
                                    { label: 'Timezone', value: result.geographic_details?.timezone || 'N/A', icon: <MapPin size={14} /> },
                                ].map((item, idx) => (
                                    <div key={idx} style={{ 
                                        display: 'flex', 
                                        justifyContent: 'space-between', 
                                        alignItems: 'center',
                                        padding: '0.6rem 0.75rem',
                                        background: 'hsl(var(--bg-secondary))',
                                        borderRadius: 'var(--radius-md)',
                                        border: '1px solid hsl(var(--border-color))'
                                    }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                            <span style={{ color: 'hsl(var(--text-muted))' }}>{item.icon}</span>
                                            <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>{item.label}</span>
                                        </div>
                                        <span style={{ fontSize: '0.8rem', fontFamily: 'monospace', color: 'hsl(var(--text-secondary))', textTransform: 'capitalize' }}>
                                            {item.value}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </Card>
                    </div>

                    {/* ROW 3: Risk Factors as Severity Cards */}
                    {result.risk_assessment.factors.length > 0 && (
                        <Card title={`Risk Factors (${result.risk_assessment.factors.length})`}>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                                {result.risk_assessment.factors.map((factor: RiskFactor, idx: number) => {
                                    const severity = getFactorSeverity(factor.impact);
                                    const style = severityStyles[severity];
                                    return (
                                        <div key={idx} style={{
                                            display: 'flex',
                                            alignItems: 'center',
                                            gap: '0.5rem',
                                            padding: '0.6rem 0.75rem',
                                            background: style.bg,
                                            borderRadius: 'var(--radius-md)',
                                            border: `1px solid ${style.border}`,
                                            color: style.color,
                                            fontSize: '0.8rem',
                                            fontWeight: 600
                                        }}>
                                            {style.icon}
                                            <span style={{ flex: 1 }}>{factor.name}</span>
                                            <span style={{ 
                                                fontFamily: 'monospace', 
                                                fontWeight: 800, 
                                                fontSize: '0.75rem',
                                                padding: '0.1rem 0.4rem',
                                                background: `${style.color}15`,
                                                borderRadius: 'var(--radius-sm)'
                                            }}>
                                                +{factor.impact}
                                            </span>
                                        </div>
                                    );
                                })}
                            </div>
                        </Card>
                    )}

                    {/* ROW 4: Network + Location Tables */}
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                        {/* Network Details */}
                        <Card title="Network Details">
                            <table className="data-table">
                                <thead>
                                    <tr>
                                        <th style={{ width: '40%' }}>Property</th>
                                        <th>Value</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr><td style={{ fontWeight: 600 }}>IP Address</td><td style={{ fontFamily: 'monospace', color: 'hsl(var(--color-primary))' }}>{result.ip}</td></tr>
                                    <tr><td style={{ fontWeight: 600 }}>ISP</td><td>{result.network_info?.isp}</td></tr>
                                    <tr><td style={{ fontWeight: 600 }}>Organization</td><td>{result.network_info?.organization}</td></tr>
                                    <tr><td style={{ fontWeight: 600 }}>Domain</td><td style={{ fontFamily: 'monospace' }}>{result.network_info?.domain}</td></tr>
                                    <tr><td style={{ fontWeight: 600 }}>ASN</td><td style={{ fontFamily: 'monospace' }}>{result.network_info?.asn}</td></tr>
                                    <tr><td style={{ fontWeight: 600 }}>ASN Name</td><td>{result.network_info?.asn_name}</td></tr>
                                    <tr><td style={{ fontWeight: 600 }}>Network Range</td><td style={{ fontFamily: 'monospace' }}>{result.network_info?.network_range}</td></tr>
                                </tbody>
                            </table>
                        </Card>

                        {/* Location & History */}
                        <Card title="Location & History">
                            <table className="data-table">
                                <thead>
                                    <tr>
                                        <th style={{ width: '40%' }}>Property</th>
                                        <th>Value</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr><td style={{ fontWeight: 600 }}>Country</td><td>{result.geographic_details?.country} ({result.geographic_details?.country_code})</td></tr>
                                    <tr><td style={{ fontWeight: 600 }}>Region</td><td>{result.geographic_details?.region_name}</td></tr>
                                    <tr><td style={{ fontWeight: 600 }}>City</td><td>{result.geographic_details?.city}</td></tr>
                                    <tr><td style={{ fontWeight: 600 }}>Coordinates</td><td style={{ fontFamily: 'monospace' }}>{result.geographic_details?.latitude}, {result.geographic_details?.longitude}</td></tr>
                                    <tr><td style={{ fontWeight: 600 }}>Continent</td><td>{result.geographic_details?.continent}</td></tr>
                                    <tr><td style={{ fontWeight: 600 }}>Total Reports</td><td style={{ fontWeight: 700, color: (result.abuse_history?.total_reports || 0) > 0 ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))' }}>{result.abuse_history?.total_reports || 0}</td></tr>
                                    <tr><td style={{ fontWeight: 600 }}>Last Reported</td><td>{result.threat_intelligence?.last_reported || 'Never'}</td></tr>
                                </tbody>
                            </table>
                        </Card>
                    </div>

                    {/* ROW 5: Port Scan */}
                    <Card title="Port Scan Results">
                        {result.port_scan?.open_ports?.length > 0 ? (
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: '0.5rem' }}>
                                {result.port_scan.open_ports.map((port: number) => (
                                    <div key={port} style={{
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        alignItems: 'center',
                                        padding: '0.6rem 0.75rem',
                                        background: 'hsla(var(--color-error), 0.04)',
                                        borderRadius: 'var(--radius-md)',
                                        border: '1px solid hsla(var(--color-error), 0.15)'
                                    }}>
                                        <div>
                                            <span style={{ fontFamily: 'monospace', fontWeight: 800, color: 'hsl(var(--color-primary))' }}>{port}</span>
                                            <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))', marginLeft: '0.5rem' }}>
                                                {result.port_scan.services_detected?.[port] || 'Unknown'}
                                            </span>
                                        </div>
                                        <span style={{ 
                                            padding: '0.15rem 0.4rem', 
                                            background: 'hsl(var(--color-error-light))', 
                                            color: 'hsl(var(--color-error))', 
                                            borderRadius: 'var(--radius-sm)', 
                                            fontSize: '0.65rem', 
                                            fontWeight: 700 
                                        }}>OPEN</span>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <div style={{ padding: '2rem', textAlign: 'center', color: 'hsl(var(--text-muted))' }}>
                                <ShieldCheck size={24} style={{ marginBottom: '0.5rem', opacity: 0.5 }} />
                                <p>No open ports detected in common range.</p>
                            </div>
                        )}
                    </Card>
                </div>
            )}


        </div>
    );
};
