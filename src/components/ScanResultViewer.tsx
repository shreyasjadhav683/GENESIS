
import { Card } from './Card';
import { 
    ShieldAlert, ShieldCheck, AlertTriangle, AlertCircle, Trash2, CheckCircle,
    Link, Lock, Unlock, ArrowRight, XCircle, Globe, Bug, Clock, Shield, Info,
    Activity, Radio, FileWarning,
    FileCode, MapPin, Camera, HardDrive, Eye, EyeOff,
    Code, Terminal, Hash, ExternalLink, BarChart3, Lightbulb, ChevronDown,
    Mail, Server
} from 'lucide-react';
import React, { useState } from 'react';

// --- Helper Functions from UrlScanner ---

const getScoreColor = (score: number) => {
    if (score >= 80) return 'hsl(var(--color-success))';
    if (score >= 50) return 'hsl(var(--color-warning))';
    return 'hsl(var(--color-error))';
};

const getRiskColor = (score: number) => {
    if (score >= 70) return 'hsl(var(--color-error))';
    if (score >= 40) return 'hsl(var(--color-warning))';
    if (score >= 15) return 'hsl(var(--color-info))';
    return 'hsl(var(--color-success))';
};



const getFlagSeverity = (flag: string) => {
    const upper = flag.toUpperCase();
    if (upper.includes('CRITICAL') || upper.includes('MALICIOUS') || upper.includes('PHISHING') || upper.includes('MALWARE') || upper.includes('EXPLOIT')) return 'critical';
    if (upper.includes('BRAND') || upper.includes('HOMOGRAPH') || upper.includes('PASSWORD') || upper.includes('EXTERNAL')) return 'high';
    if (upper.includes('SUSPICIOUS') || upper.includes('EXCESSIVE') || upper.includes('HIDDEN') || upper.includes('OBFUSCATED') || upper.includes('MULTIPLE') || upper.includes('WEAK') || upper.includes('NEWLY') || upper.includes('RECENTLY')) return 'medium';
    return 'low';
};

const severityStyles: Record<string, { bg: string; color: string; border: string; icon: React.ReactNode }> = {
    critical: { 
        bg: 'hsla(0, 85%, 50%, 0.08)', 
        color: 'hsl(0, 85%, 50%)', 
        border: 'hsla(0, 85%, 50%, 0.25)',
        icon: <ShieldAlert size={16} />
    },
    high: { 
        bg: 'hsla(15, 90%, 55%, 0.08)', 
        color: 'hsl(15, 90%, 55%)', 
        border: 'hsla(15, 90%, 55%, 0.25)',
        icon: <AlertTriangle size={16} />
    },
    medium: { 
        bg: 'hsla(40, 90%, 50%, 0.08)', 
        color: 'hsl(40, 90%, 50%)', 
        border: 'hsla(40, 90%, 50%, 0.25)',
        icon: <Info size={16} />
    },
    low: { 
        bg: 'hsla(210, 60%, 50%, 0.08)', 
        color: 'hsl(210, 60%, 50%)', 
        border: 'hsla(210, 60%, 50%, 0.25)',
        icon: <Activity size={16} />
    }
};

const getThreatBadge = (status: string) => {
    const s = status?.toUpperCase() || '';
    if (s.includes('MALICIOUS') || s.includes('THREAT') || s.includes('PHISHING_VERIFIED'))
        return { label: 'THREAT', bg: 'hsl(var(--color-error-light))', color: 'hsl(var(--color-error))' };
    if (s.includes('SUSPECTED'))
        return { label: 'SUSPECT', bg: 'hsl(var(--color-warning-light))', color: 'hsl(var(--color-warning))' };
    if (s === 'CLEAN' || s === 'NOT_FOUND')
        return { label: 'CLEAN', bg: 'hsl(var(--color-success-light))', color: 'hsl(var(--color-success))' };
    if (s === 'NOT_CONFIGURED')
        return { label: 'N/A', bg: 'hsl(var(--bg-secondary))', color: 'hsl(var(--text-muted))' };
    return { label: 'ERROR', bg: 'hsl(var(--bg-secondary))', color: 'hsl(var(--text-muted))' };
};




interface ScanResultViewerProps {
    scanType: string;
    target: string;
    result: any;
    createdAt: string;
}

const getSeverityColor = (severity: string): string => {
    const colors: Record<string, string> = {
        'Critical': 'hsl(var(--color-error))',
        'High': '#f97316',
        'Medium': 'hsl(var(--color-warning))',
        'Low': 'hsl(var(--color-success))',
        'Safe': 'hsl(var(--color-success))',
    };
    return colors[severity] || 'hsl(var(--text-muted))';
};

// Render IP Scan Results
const renderIPScanResult = (result: any) => {
    if (!result) return <p>No result data available</p>;
    
    const riskAssessment = result.risk_assessment || {};
    const threatIntel = result.threat_intelligence || {};
    const networkInfo = result.network_info || {};
    const geoDetails = result.geographic_details || {};
    const abuseHistory = result.abuse_history || {};
    const portScan = result.port_scan || {};
    const dnsInfo = result.dns_info || {};

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {/* Security Assessment */}
            <Card title="Security Assessment">
                <div style={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    justifyContent: 'space-between',
                    padding: '1rem',
                    background: 'hsl(var(--bg-secondary))',
                    borderRadius: 'var(--radius-lg)',
                    marginBottom: '1.5rem'
                }}>
                    <div>
                        <span style={{ color: 'hsl(var(--text-muted))', fontSize: '0.75rem', textTransform: 'uppercase' }}>
                            Risk Score
                        </span>
                        <p style={{ 
                            fontSize: '2rem', 
                            fontWeight: 900, 
                            color: getSeverityColor(riskAssessment.severity || 'Low')
                        }}>
                            {riskAssessment.score || 0}/100
                        </p>
                    </div>
                    <span style={{ 
                        padding: '0.5rem 1rem', 
                        borderRadius: 'var(--radius-full)',
                        background: `${getSeverityColor(riskAssessment.severity || 'Low')}20`,
                        color: getSeverityColor(riskAssessment.severity || 'Low'),
                        fontWeight: 700,
                        fontSize: '0.875rem',
                        border: `1px solid ${getSeverityColor(riskAssessment.severity || 'Low')}40`
                    }}>
                        {riskAssessment.severity || 'Unknown'}
                    </span>
                </div>

                <table className="data-table">
                    <thead>
                        <tr>
                            <th style={{ width: '30%' }}>Property</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Recommendation</td>
                            <td style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                {riskAssessment.is_malicious && <span style={{ color: 'hsl(var(--color-error))' }}>⛔</span>}
                                {riskAssessment.recommendation || 'N/A'}
                            </td>
                        </tr>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Abuse Confidence</td>
                            <td>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                    <div style={{ width: '120px', height: '8px', background: 'hsl(var(--bg-tertiary))', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
                                        <div style={{ 
                                            width: `${threatIntel.abuse_confidence_score || 0}%`, 
                                            height: '100%', 
                                            background: (threatIntel.abuse_confidence_score || 0) > 50 ? 'hsl(var(--color-error))' : 'hsl(var(--color-warning))'
                                        }} />
                                    </div>
                                    <span>{threatIntel.abuse_confidence_score || 0}%</span>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Fraud Score</td>
                            <td>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                    <div style={{ width: '120px', height: '8px', background: 'hsl(var(--bg-tertiary))', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
                                        <div style={{ 
                                            width: `${threatIntel.fraud_score || 0}%`, 
                                            height: '100%', 
                                            background: 'hsl(var(--text-muted))'
                                        }} />
                                    </div>
                                    <span>{threatIntel.fraud_score || 0}%</span>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Indicators</td>
                            <td>
                                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                                    {threatIntel.is_proxy && <span style={{ padding: '0.25rem 0.5rem', fontSize: '0.7rem', fontWeight: 700, background: 'hsl(var(--color-primary))', color: 'white', borderRadius: 'var(--radius-sm)' }}>Proxy</span>}
                                    {threatIntel.is_tor_exit && <span style={{ padding: '0.25rem 0.5rem', fontSize: '0.7rem', fontWeight: 700, background: 'hsl(var(--color-secondary))', color: 'white', borderRadius: 'var(--radius-sm)' }}>Tor Exit</span>}
                                    {threatIntel.is_vpn && <span style={{ padding: '0.25rem 0.5rem', fontSize: '0.7rem', fontWeight: 700, background: 'hsl(var(--color-info))', color: 'white', borderRadius: 'var(--radius-sm)' }}>VPN</span>}
                                    {threatIntel.is_blacklisted && <span style={{ padding: '0.25rem 0.5rem', fontSize: '0.7rem', fontWeight: 700, background: 'hsl(var(--color-error))', color: 'white', borderRadius: 'var(--radius-sm)' }}>BLACKLISTED</span>}
                                    {threatIntel.is_datacenter && <span style={{ padding: '0.25rem 0.5rem', fontSize: '0.7rem', fontWeight: 700, background: 'hsl(var(--color-warning))', color: 'black', borderRadius: 'var(--radius-sm)' }}>Datacenter</span>}
                                    {!threatIntel.is_proxy && !threatIntel.is_tor_exit && !threatIntel.is_vpn && !threatIntel.is_blacklisted && <span style={{ color: 'hsl(var(--text-muted))' }}>None detected</span>}
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Usage Type</td>
                            <td>{threatIntel.usage_type || 'Unknown'}</td>
                        </tr>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Connection Type</td>
                            <td>{threatIntel.connection_type || 'Unknown'}</td>
                        </tr>
                    </tbody>
                </table>
            </Card>

            {/* Risk Factors */}
            {riskAssessment.factors && riskAssessment.factors.length > 0 && (
                <Card title="Risk Factors">
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th>Factor</th>
                                <th>Impact</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {riskAssessment.factors.map((factor: any, idx: number) => (
                                <tr key={idx}>
                                    <td style={{ fontWeight: 600 }}>{factor.name}</td>
                                    <td style={{ color: 'hsl(var(--color-secondary))' }}>+{factor.impact}</td>
                                    <td style={{ color: 'hsl(var(--text-secondary))' }}>{factor.description}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </Card>
            )}

            {/* Network & Location */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem' }}>
                <Card title="Network Details">
                    <table className="data-table">
                        <thead>
                            <tr><th>Property</th><th>Value</th></tr>
                        </thead>
                        <tbody>
                            <tr><td style={{ fontWeight: 600 }}>IP Address</td><td style={{ color: 'hsl(var(--color-primary))', fontFamily: 'monospace' }}>{result.ip}</td></tr>
                            <tr><td style={{ fontWeight: 600 }}>ISP</td><td>{networkInfo.isp || 'N/A'}</td></tr>
                            <tr><td style={{ fontWeight: 600 }}>Organization</td><td>{networkInfo.organization || 'N/A'}</td></tr>
                            <tr><td style={{ fontWeight: 600 }}>Domain</td><td>{networkInfo.domain || 'N/A'}</td></tr>
                            <tr><td style={{ fontWeight: 600 }}>ASN</td><td>{networkInfo.asn || 'N/A'}</td></tr>
                            <tr><td style={{ fontWeight: 600 }}>ASN Name</td><td>{networkInfo.asn_name || 'N/A'}</td></tr>
                            <tr><td style={{ fontWeight: 600 }}>Network Range</td><td>{networkInfo.network_range || 'N/A'}</td></tr>
                            <tr><td style={{ fontWeight: 600 }}>Reverse DNS</td><td style={{ wordBreak: 'break-all' }}>{dnsInfo.reverse_dns || 'N/A'}</td></tr>
                        </tbody>
                    </table>
                </Card>

                <Card title="Location & History">
                    <table className="data-table">
                        <thead>
                            <tr><th>Property</th><th>Value</th></tr>
                        </thead>
                        <tbody>
                            <tr><td style={{ fontWeight: 600 }}>Country</td><td>{geoDetails.country || 'N/A'} {geoDetails.country_code ? `(${geoDetails.country_code})` : ''}</td></tr>
                            <tr><td style={{ fontWeight: 600 }}>Region</td><td>{geoDetails.region_name || geoDetails.region || 'N/A'}</td></tr>
                            <tr><td style={{ fontWeight: 600 }}>City</td><td>{geoDetails.city || 'N/A'}</td></tr>
                            <tr><td style={{ fontWeight: 600 }}>Timezone</td><td>{geoDetails.timezone || 'N/A'}</td></tr>
                            <tr><td style={{ fontWeight: 600 }}>Coordinates</td><td>{geoDetails.latitude && geoDetails.longitude ? `${geoDetails.latitude}, ${geoDetails.longitude}` : 'N/A'}</td></tr>
                            <tr><td style={{ fontWeight: 600 }}>Continent</td><td>{geoDetails.continent || 'N/A'}</td></tr>
                            <tr><td style={{ fontWeight: 600 }}>Total Reports</td><td>{abuseHistory.total_reports || 0}</td></tr>
                            <tr><td style={{ fontWeight: 600 }}>Last Reported</td><td>{abuseHistory.last_reported_at || threatIntel.last_reported || 'Never'}</td></tr>
                        </tbody>
                    </table>
                </Card>
            </div>

            {/* Port Scan */}
            {portScan.open_ports && portScan.open_ports.length > 0 && (
                <Card title="Port Scan Results">
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Service</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {portScan.open_ports.map((port: number) => (
                                <tr key={port}>
                                    <td style={{ color: 'hsl(var(--color-primary))', fontWeight: 600 }}>{port}</td>
                                    <td>{portScan.services_detected?.[port] || 'Unknown'}</td>
                                    <td><span style={{ padding: '0.25rem 0.5rem', fontSize: '0.7rem', fontWeight: 700, background: 'hsl(var(--color-success))', color: 'white', borderRadius: 'var(--radius-sm)' }}>OPEN</span></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </Card>
            )}
        </div>
    );
};

// Render URL Scan Results
const renderURLScanResult = (result: any) => {
    if (!result) return <p>No result data available</p>;
    
    // Check if we have the new rich data structure or need to fallback/adapt
    // The rich UI expects: risk_score, malicious, risk_level, domain, ip_address, status_code, performance, final_url, threat_intel, malware_signatures, security_headers_analysis, flags, domain_info, ssl_info, redirect_chain, content_analysis
    
    const sha = result.security_headers_analysis;
    const threatSources = [
        { name: 'URLhaus', key: 'urlhaus' },
        { name: 'PhishTank', key: 'phishtank' },
        { name: 'Safe Browsing', key: 'google_safe_browsing' },
    ];

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            
             {/* Header Status */}
             <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                {result.malicious ? 
                    <ShieldAlert size={24} style={{ color: 'hsl(var(--color-error))' }} /> :
                    <ShieldCheck size={24} style={{ color: 'hsl(var(--color-success))' }} />
                }
                <span style={{ 
                    fontWeight: 700, 
                    color: result.malicious ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))',
                    fontSize: '1.25rem'
                }}>
                    {result.malicious ? 'Threats Detected' : 'URL Appears Safe'}
                </span>
            </div>

            {/* ═══════════════════════════════════════════════════ */}
            {/* ROW 1: Threat Grade + Risk Score + Summary */}
            {/* ═══════════════════════════════════════════════════ */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem' }}>
                {/* Threat Grade */}
                <Card>
                    <div style={{ textAlign: 'center', padding: '1rem 0' }}>
                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>
                            Threat Level
                        </p>
                        <p style={{ 
                            fontSize: '3.5rem', 
                            fontWeight: 900, 
                            color: result.malicious ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))',
                            lineHeight: 1
                        }}>
                            {result.malicious ? '⚠' : '✓'}
                        </p>
                        <p style={{ 
                            marginTop: '0.5rem',
                            padding: '0.25rem 0.75rem',
                            borderRadius: 'var(--radius-full)',
                            display: 'inline-block',
                            fontSize: '0.75rem',
                            fontWeight: 800,
                            background: result.malicious ? 'hsl(var(--color-error-light))' : 'hsl(var(--color-success-light))',
                            color: result.malicious ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))'
                        }}>
                            {result.risk_level || 'UNKNOWN'}
                        </p>
                    </div>
                </Card>

                {/* Risk Score Dial */}
                <Card>
                    <div style={{ textAlign: 'center', padding: '1rem 0' }}>
                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>
                            Risk Score
                        </p>
                        <p style={{ 
                            fontSize: '3rem', 
                            fontWeight: 900, 
                            color: getRiskColor(result.risk_score || 0),
                            lineHeight: 1
                        }}>
                            {result.risk_score || 0}
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
                                width: `${result.risk_score || 0}%`,
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
                                <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Domain</p>
                                <p style={{ fontSize: '0.8rem', fontWeight: 600, fontFamily: 'monospace', wordBreak: 'break-all' }}>{result.domain}</p>
                            </div>
                            <div style={{ padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                                <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>IP Address</p>
                                <p style={{ fontSize: '0.8rem', fontWeight: 600, fontFamily: 'monospace' }}>{result.ip_address || 'N/A'}</p>
                            </div>
                            <div style={{ padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                                <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>HTTP Status</p>
                                <p style={{ fontSize: '0.8rem', fontWeight: 700, color: result.status_code >= 400 ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))' }}>
                                    {result.status_code || 'N/A'}
                                </p>
                            </div>
                            <div style={{ padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                                <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Load Time</p>
                                <p style={{ fontSize: '0.8rem', fontWeight: 600, fontFamily: 'monospace', color: 'hsl(var(--color-info))' }}>
                                    {result.performance?.load_time_ms || 0}ms
                                </p>
                            </div>
                        </div>
                        {/* Final URL */}
                        <div style={{ marginTop: '0.5rem', padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                            <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Final URL</p>
                            <p style={{ fontSize: '0.75rem', fontFamily: 'monospace', wordBreak: 'break-all', color: 'hsl(var(--color-primary))' }}>
                                {result.final_url}
                            </p>
                        </div>
                    </div>
                </Card>
            </div>

            {/* ═══════════════════════════════════════════════════ */}
            {/* ROW 2: Threat Intel + Security Headers Grade */}
            {/* ═══════════════════════════════════════════════════ */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem' }}>
                {/* Threat Intelligence */}
                <Card title="Threat Intelligence">
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                        {threatSources.map(source => {
                            const status = result.threat_intel?.[source.key]?.status || 'UNKNOWN';
                            const badge = getThreatBadge(status);
                            return (
                                <div key={source.key} style={{ 
                                    display: 'flex', 
                                    justifyContent: 'space-between', 
                                    alignItems: 'center',
                                    padding: '0.75rem 1rem',
                                    background: 'hsl(var(--bg-secondary))',
                                    borderRadius: 'var(--radius-md)',
                                    border: '1px solid hsl(var(--border-color))'
                                }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                        <Radio size={16} style={{ color: 'hsl(var(--text-muted))' }} />
                                        <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{source.name}</span>
                                    </div>
                                    <span style={{ 
                                        padding: '0.2rem 0.6rem', 
                                        borderRadius: 'var(--radius-full)',
                                        background: badge.bg,
                                        color: badge.color,
                                        fontWeight: 800,
                                        fontSize: '0.65rem',
                                        letterSpacing: '0.05em'
                                    }}>
                                        {badge.label}
                                    </span>
                                </div>
                            );
                        })}
                        {/* Malware Signatures */}
                        <div style={{ 
                            display: 'flex', 
                            justifyContent: 'space-between', 
                            alignItems: 'center',
                            padding: '0.75rem 1rem',
                            background: 'hsl(var(--bg-secondary))',
                            borderRadius: 'var(--radius-md)',
                            border: '1px solid hsl(var(--border-color))'
                        }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                <Bug size={16} style={{ color: 'hsl(var(--text-muted))' }} />
                                <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>Malware Signatures</span>
                            </div>
                            <span style={{ 
                                padding: '0.2rem 0.6rem', 
                                borderRadius: 'var(--radius-full)',
                                background: result.malware_signatures?.clean ? 'hsl(var(--color-success-light))' : 'hsl(var(--color-error-light))',
                                color: result.malware_signatures?.clean ? 'hsl(var(--color-success))' : 'hsl(var(--color-error))',
                                fontWeight: 800,
                                fontSize: '0.65rem',
                                letterSpacing: '0.05em'
                            }}>
                                {result.malware_signatures?.clean !== false ? 'CLEAN' : `${result.malware_signatures?.detections?.length || 0} FOUND`}
                            </span>
                        </div>
                    </div>
                </Card>

                {/* Security Headers Score */}
                <Card title="Security Headers">
                    {sha ? (
                        <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', marginBottom: '1rem' }}>
                                <div style={{ textAlign: 'center' }}>
                                    <p style={{ fontSize: '3rem', fontWeight: 900, color: getScoreColor(sha.score), lineHeight: 1 }}>
                                        {sha.grade}
                                    </p>
                                    <p style={{ fontSize: '0.85rem', fontWeight: 600, color: 'hsl(var(--text-secondary))' }}>{sha.score}/100</p>
                                </div>
                                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                                    <div style={{ 
                                        padding: '0.5rem 0.75rem',
                                        background: 'hsl(var(--color-success-light))',
                                        borderRadius: 'var(--radius-sm)',
                                        border: '1px solid hsla(var(--color-success), 0.2)',
                                        display: 'flex', justifyContent: 'space-between'
                                    }}>
                                        <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))' }}>Present</span>
                                        <span style={{ fontWeight: 800, color: 'hsl(var(--color-success))' }}>{sha.present_count}</span>
                                    </div>
                                    <div style={{ 
                                        padding: '0.5rem 0.75rem',
                                        background: 'hsl(var(--color-error-light))',
                                        borderRadius: 'var(--radius-sm)',
                                        border: '1px solid hsla(var(--color-error), 0.2)',
                                        display: 'flex', justifyContent: 'space-between'
                                    }}>
                                        <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))' }}>Missing</span>
                                        <span style={{ fontWeight: 800, color: 'hsl(var(--color-error))' }}>{sha.missing_count}</span>
                                    </div>
                                </div>
                            </div>
                            {/* Header list */}
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                                {sha.headers?.map((h: any, idx: number) => (
                                    <div key={idx} style={{ 
                                        display: 'flex', 
                                        alignItems: 'center', 
                                        gap: '0.5rem',
                                        padding: '0.35rem 0.5rem',
                                        borderRadius: 'var(--radius-sm)',
                                        background: h.status === 'present' ? 'hsla(var(--color-success), 0.04)' : 'hsla(var(--color-error), 0.04)'
                                    }}>
                                        {h.status === 'present' ? 
                                            <CheckCircle size={14} style={{ color: 'hsl(var(--color-success))', flexShrink: 0 }} /> :
                                            <XCircle size={14} style={{ color: 'hsl(var(--color-error))', flexShrink: 0 }} />
                                        }
                                        <span style={{ fontSize: '0.75rem', fontFamily: 'monospace', fontWeight: 500 }}>{h.name}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    ) : (
                        <p style={{ color: 'hsl(var(--text-muted))', textAlign: 'center', padding: '2rem' }}>No header data available</p>
                    )}
                </Card>
            </div>

            {/* ═══════════════════════════════════════════════════ */}
            {/* ROW 3: Flags & Alerts */}
            {/* ═══════════════════════════════════════════════════ */}
            {result.flags && result.flags.length > 0 && (
                <Card title={`Threat Flags (${result.flags.length})`}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                        {result.flags.map((flag: string, idx: number) => {
                            const severity = getFlagSeverity(flag);
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
                                    <span style={{ flex: 1 }}>{flag}</span>
                                </div>
                            );
                        })}
                    </div>
                </Card>
            )}

            {/* ═══════════════════════════════════════════════════ */}
            {/* ROW 4: Domain Info + SSL + Redirect Chain */}
            {/* ═══════════════════════════════════════════════════ */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem' }}>
                {/* Domain & WHOIS Info */}
                <Card title="Domain & WHOIS">
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th style={{ width: '40%' }}>Property</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td style={{ fontWeight: 600 }}>Domain</td>
                                <td style={{ fontFamily: 'monospace' }}>{result.domain}</td>
                            </tr>
                            <tr>
                                <td style={{ fontWeight: 600 }}>IP Address</td>
                                <td style={{ fontFamily: 'monospace' }}>{result.ip_address || 'Unresolved'}</td>
                            </tr>
                            <tr>
                                <td style={{ fontWeight: 600 }}>Reverse DNS</td>
                                <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{result.dns_info?.reverse_dns || 'N/A'}</td>
                            </tr>
                            {result.domain_info?.age_days != null && (
                                <tr>
                                    <td style={{ fontWeight: 600 }}>
                                        <span style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                                            <Clock size={14} /> Domain Age
                                        </span>
                                    </td>
                                    <td>
                                        <span style={{ 
                                            fontWeight: 700,
                                            color: result.domain_info.age_days < 30 ? 'hsl(var(--color-error))' : 
                                                    result.domain_info.age_days < 365 ? 'hsl(var(--color-warning))' : 'hsl(var(--color-success))'
                                        }}>
                                            {result.domain_info.age_days} days
                                        </span>
                                    </td>
                                </tr>
                            )}
                            {result.domain_info?.registrar && (
                                <tr>
                                    <td style={{ fontWeight: 600 }}>Registrar</td>
                                    <td style={{ fontSize: '0.8rem' }}>{result.domain_info.registrar}</td>
                                </tr>
                            )}
                            {result.domain_info?.creation_date && (
                                <tr>
                                    <td style={{ fontWeight: 600 }}>Created</td>
                                    <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{result.domain_info.creation_date}</td>
                                </tr>
                            )}
                            {result.domain_info?.expiration_date && (
                                <tr>
                                    <td style={{ fontWeight: 600 }}>Expires</td>
                                    <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{result.domain_info.expiration_date}</td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </Card>

                {/* SSL & Infrastructure */}
                <Card title="SSL & Infrastructure">
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th style={{ width: '40%' }}>Property</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td style={{ fontWeight: 600 }}>SSL Status</td>
                                <td>
                                    {result.ssl_info?.valid ? 
                                        <span style={{ color: 'hsl(var(--color-success))', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                                            <Lock size={14}/> Valid HTTPS
                                        </span> :
                                        result.flags?.includes("SSL Certificate Error") ?
                                        <span style={{ color: 'hsl(var(--color-error))', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                                            <Unlock size={14}/> Invalid Certificate
                                        </span> :
                                        <span style={{ color: 'hsl(var(--text-muted))' }}>No SSL / HTTP</span>
                                    }
                                </td>
                            </tr>
                            {result.ssl_info?.valid && (
                                <>
                                    <tr>
                                        <td style={{ fontWeight: 600 }}>SSL Version</td>
                                        <td>{result.ssl_info?.version}</td>
                                    </tr>
                                    <tr>
                                        <td style={{ fontWeight: 600 }}>Cipher Suite</td>
                                        <td style={{ fontSize: '0.75rem', wordBreak: 'break-all', fontFamily: 'monospace' }}>{result.ssl_info?.cipher}</td>
                                    </tr>
                                </>
                            )}
                            <tr>
                                <td style={{ fontWeight: 600 }}>Server Header</td>
                                <td>{result.security_headers?.server || result.security_headers?.Server || 'Hidden'}</td>
                            </tr>
                            <tr>
                                <td style={{ fontWeight: 600 }}>Content Type</td>
                                <td style={{ fontSize: '0.8rem', fontFamily: 'monospace' }}>{result.content_analysis?.content_type || 'N/A'}</td>
                            </tr>
                        </tbody>
                    </table>
                </Card>
            </div>

            {/* ═══════════════════════════════════════════════════ */}
            {/* ROW 5: Redirect Chain */}
            {/* ═══════════════════════════════════════════════════ */}
            <Card title="Redirection Chain">
                {result.redirect_chain && result.redirect_chain.length > 0 ? (
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th style={{ width: '80px' }}>Step</th>
                                <th style={{ width: '100px' }}>Status</th>
                                <th>URL Location</th>
                            </tr>
                        </thead>
                        <tbody>
                            {result.redirect_chain.map((hop: any, idx: number) => (
                                <tr key={idx}>
                                    <td style={{ fontFamily: 'monospace', color: 'hsl(var(--text-muted))' }}>#{idx + 1}</td>
                                    <td>
                                        <span style={{ 
                                            padding: '0.25rem 0.5rem', 
                                            borderRadius: 'var(--radius-sm)',
                                            background: hop.status >= 300 && hop.status < 400 ? 'hsl(var(--color-warning-light))' : 'hsl(var(--color-success-light))',
                                            color: hop.status >= 300 && hop.status < 400 ? 'hsl(var(--color-warning))' : 'hsl(var(--color-success))',
                                            fontWeight: 700,
                                            fontSize: '0.75rem'
                                        }}>
                                            {hop.status}
                                        </span>
                                    </td>
                                    <td style={{ fontFamily: 'monospace', wordBreak: 'break-all', fontSize: '0.8rem' }}>{hop.url}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                ) : (
                    <div style={{ padding: '1.5rem', textAlign: 'center', color: 'hsl(var(--text-muted))' }}>
                        <ShieldCheck size={20} style={{ marginBottom: '0.25rem' }} />
                        <p>No redirects detected. Direct connection.</p>
                    </div>
                )}
            </Card>

            {/* ═══════════════════════════════════════════════════ */}
            {/* ROW 6: Content Analysis */}
            {/* ═══════════════════════════════════════════════════ */}
            <Card title="Content & Metadata">
                <table className="data-table">
                    <thead>
                        <tr>
                            <th style={{ width: '30%' }}>Property</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Page Title</td>
                            <td style={{ fontStyle: 'italic' }}>{result.content_analysis?.title || 'N/A'}</td>
                        </tr>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Meta Description</td>
                            <td style={{ fontSize: '0.8rem', color: 'hsl(var(--text-secondary))' }}>
                                {result.content_analysis?.description || 'N/A'}
                            </td>
                        </tr>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Generator</td>
                            <td>{result.content_analysis?.generator || 'Unknown'}</td>
                        </tr>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Detected Forms</td>
                            <td>
                                {result.flags?.some((f: string) => f.includes("Password")) ? 
                                    <span style={{ color: 'hsl(var(--color-error))', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                                        <Lock size={14}/> Password Field
                                    </span> : 
                                    <span style={{ color: 'hsl(var(--text-muted))' }}>No sensitive forms</span>
                                }
                            </td>
                        </tr>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Scripts / Iframes</td>
                            <td style={{ fontSize: '0.85rem' }}>
                                Scripts: <strong>{result.content_analysis?.script_count || 0}</strong>
                                {' · '}
                                Iframes: <strong>{result.content_analysis?.iframe_count || 0}</strong>
                            </td>
                        </tr>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Link Analysis</td>
                            <td style={{ fontSize: '0.85rem' }}>
                                Total: <strong>{result.content_analysis?.link_count || 0}</strong>
                                {' · '}
                                External: <strong>{result.content_analysis?.external_link_count || 0}</strong>
                            </td>
                        </tr>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Suspicious Keywords</td>
                            <td>
                                {result.content_analysis?.keywords_found?.length > 0 ? (
                                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                                        {result.content_analysis.keywords_found.map((k: string) => (
                                            <span key={k} style={{ 
                                                padding: '0.125rem 0.375rem', 
                                                background: 'hsl(var(--color-error-light))', 
                                                color: 'hsl(var(--color-error))', 
                                                borderRadius: 'var(--radius-sm)', 
                                                fontSize: '0.7rem',
                                                fontWeight: 600
                                            }}>
                                                {k}
                                            </span>
                                        ))}
                                    </div>
                                ) : (
                                    <span style={{ color: 'hsl(var(--color-success))' }}>None Found</span>
                                )}
                            </td>
                        </tr>
                    </tbody>
                </table>
            </Card>
        </div>
    );
};

// Render generic result as formatted JSON
const renderGenericResult = (result: any, scanType: string) => {
    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            <Card title={`${scanType} Results`}>
                <pre style={{
                    background: 'hsl(var(--bg-tertiary))',
                    padding: '1rem',
                    borderRadius: 'var(--radius-md)',
                    overflowX: 'auto',
                    fontFamily: 'monospace',
                    fontSize: '0.875rem',
                    color: 'hsl(var(--text-primary))',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word'
                }}>
                    {JSON.stringify(result, null, 2)}
                </pre>
            </Card>
        </div>
    );
};

// Render File Integrity Results
const renderFileIntegrityResult = (result: any) => {
    if (!result) return <p>No result data available</p>;
    
    const isClean = result.status === 'CLEAN' || result.hash_match === true;
    const statusColor = isClean ? 'hsl(var(--color-success))' : 'hsl(var(--color-error))';
    const statusBg = isClean ? 'hsl(var(--color-success-light))' : 'hsl(var(--color-error-light))';
    
    const formatBytes = (bytes: number): string => {
        if (!bytes) return 'N/A';
        if (bytes < 1024) return bytes + ' bytes';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {/* Status Header */}
            <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: '0.75rem',
                padding: '1rem',
                background: statusBg,
                borderRadius: 'var(--radius-lg)',
                border: `1px solid ${statusColor}40`
            }}>
                {isClean ? (
                    <ShieldCheck size={24} style={{ color: statusColor }} />
                ) : (
                    <ShieldAlert size={24} style={{ color: statusColor }} />
                )}
                <span style={{ fontWeight: 700, color: statusColor }}>
                    Status: {result.status || (isClean ? 'CLEAN' : 'MODIFIED')}
                </span>
            </div>

            {/* Details Message */}
            {result.details && (
                <div style={{ 
                    padding: '1rem',
                    background: statusBg,
                    borderRadius: 'var(--radius-md)',
                    borderLeft: `4px solid ${statusColor}`
                }}>
                    <p style={{ fontWeight: 600, marginBottom: '0.25rem' }}>{result.details}</p>
                    <p style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))' }}>
                        Scan Time: {result.scan_time ? new Date(result.scan_time).toLocaleString() : 'N/A'}
                    </p>
                </div>
            )}

            {/* File Details Table */}
            <Card>
                <table className="data-table">
                    <thead>
                        <tr>
                            <th style={{ width: '30%' }}>Property</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Filename</td>
                            <td>{result.filename || 'N/A'}</td>
                        </tr>
                        <tr>
                            <td style={{ fontWeight: 600 }}>File Size</td>
                            <td>{formatBytes(result.size_bytes)}</td>
                        </tr>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Current SHA-256</td>
                            <td style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'hsl(var(--color-primary))', wordBreak: 'break-all' }}>
                                {result.hash || result.current_hash || 'N/A'}
                            </td>
                        </tr>
                        {result.current_md5 && (
                            <tr>
                                <td style={{ fontWeight: 600 }}>Current MD5</td>
                                <td style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'hsl(var(--color-secondary))', wordBreak: 'break-all' }}>
                                    {result.current_md5}
                                </td>
                            </tr>
                        )}
                        {result.baseline_hash && (
                            <tr>
                                <td style={{ fontWeight: 600 }}>Baseline SHA-256</td>
                                <td style={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                                    {result.baseline_hash}
                                </td>
                            </tr>
                        )}
                        {result.baseline_date && (
                            <tr>
                                <td style={{ fontWeight: 600 }}>Baseline Date</td>
                                <td>{new Date(result.baseline_date).toLocaleString()}</td>
                            </tr>
                        )}
                        <tr>
                            <td style={{ fontWeight: 600 }}>Hash Match</td>
                            <td>
                                <span style={{ 
                                    padding: '0.25rem 0.75rem', 
                                    borderRadius: 'var(--radius-full)',
                                    background: isClean ? 'hsl(var(--color-success))' : 'hsl(var(--color-error))',
                                    color: 'white',
                                    fontWeight: 700,
                                    fontSize: '0.75rem'
                                }}>
                                    {isClean ? '✓ MATCH' : '✗ MISMATCH'}
                                </span>
                            </td>
                        </tr>
                        {result.algorithm && (
                            <tr>
                                <td style={{ fontWeight: 600 }}>Algorithm</td>
                                <td style={{ textTransform: 'uppercase' }}>{result.algorithm}</td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </Card>
        </div>
    );
};

// Render Browser Extension Scan Results
const RenderExtensionScanResult = ({ result }: { result: any }) => {
    const [expandedExt, setExpandedExt] = useState<string | null>(null);

    if (!result || !result.extensions) return <p>No result data available</p>;

    const summary = result.summary || {};
    const criticalCount = summary.critical || 0;
    const highCount = summary.high || 0;
    const mediumCount = summary.medium || 0;
    const totalCount = summary.total || 0;
    const extensions = result.extensions || [];
    
    const getRiskColor = (level: string) => {
        switch (level?.toUpperCase()) {
            case 'CRITICAL': return 'hsl(var(--color-error))';
            case 'HIGH': return '#f97316';
            case 'MEDIUM': return 'hsl(var(--color-warning))';
            case 'LOW': return 'hsl(var(--color-info))';
            default: return 'hsl(var(--color-success))';
        }
    };

    const getRiskBg = (level: string) => {
        switch (level?.toUpperCase()) {
            case 'CRITICAL': return 'hsla(var(--color-error), 0.1)';
            case 'HIGH': return 'rgba(249, 115, 22, 0.1)';
            case 'MEDIUM': return 'hsla(var(--color-warning), 0.1)';
            case 'LOW': return 'hsla(var(--color-info), 0.1)';
            default: return 'hsla(var(--color-success), 0.1)';
        }
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
             {/* Summary Cards */}
             <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '1rem' }}>
                <Card style={{ textAlign: 'center', padding: '1.5rem' }}>
                    <h3 style={{ fontSize: '2rem', fontWeight: 900, color: 'hsl(var(--text-primary))' }}>{totalCount}</h3>
                    <p style={{ fontSize: '0.875rem', color: 'hsl(var(--text-muted))' }}>Total Scanned</p>
                </Card>
                <Card style={{ textAlign: 'center', padding: '1.5rem', background: criticalCount > 0 ? getRiskBg('CRITICAL') : undefined, borderColor: criticalCount > 0 ? getRiskColor('CRITICAL') : undefined }}>
                    <h3 style={{ fontSize: '2rem', fontWeight: 900, color: criticalCount > 0 ? getRiskColor('CRITICAL') : 'hsl(var(--text-muted))' }}>{criticalCount}</h3>
                    <p style={{ fontSize: '0.875rem', color: criticalCount > 0 ? getRiskColor('CRITICAL') : 'hsl(var(--text-muted))' }}>Critical Risks</p>
                </Card>
                <Card style={{ textAlign: 'center', padding: '1.5rem', background: highCount > 0 ? getRiskBg('HIGH') : undefined, borderColor: highCount > 0 ? getRiskColor('HIGH') : undefined }}>
                    <h3 style={{ fontSize: '2rem', fontWeight: 900, color: highCount > 0 ? getRiskColor('HIGH') : 'hsl(var(--text-muted))' }}>{highCount}</h3>
                    <p style={{ fontSize: '0.875rem', color: highCount > 0 ? getRiskColor('HIGH') : 'hsl(var(--text-muted))' }}>High Risks</p>
                </Card>
                <Card style={{ textAlign: 'center', padding: '1.5rem' }}>
                    <h3 style={{ fontSize: '2rem', fontWeight: 900, color: 'hsl(var(--text-primary))' }}>{mediumCount}</h3>
                    <p style={{ fontSize: '0.875rem', color: 'hsl(var(--text-muted))' }}>Medium Risks</p>
                </Card>
            </div>

            {/* Remediation Summary if critical/high risks found */}
            {(criticalCount > 0 || highCount > 0) && (
                <div style={{
                    padding: '1.5rem',
                    background: 'hsl(var(--bg-card))',
                    border: '1px solid hsl(var(--color-error))',
                    borderRadius: 'var(--radius-lg)',
                    position: 'relative',
                    overflow: 'hidden'
                }}>
                    <div style={{ 
                        position: 'absolute', 
                        top: 0, 
                        left: 0, 
                        width: '4px', 
                        height: '100%', 
                        background: 'hsl(var(--color-error))' 
                    }} />
                    
                    <h3 style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        gap: '0.75rem', 
                        color: 'hsl(var(--color-error))',
                        fontSize: '1.1rem',
                        marginBottom: '1rem'
                    }}>
                        <AlertCircle size={24} />
                        Immediate Action Required
                    </h3>
                    
                    <p style={{ marginBottom: '1rem', color: 'hsl(var(--text-secondary))' }}>
                        <strong>{criticalCount + highCount} extensions</strong> contain critical security risks.
                    </p>
                    
                    <div style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap' }}>
                        <div style={{ flex: 1, minWidth: '250px' }}>
                            <h4 style={{ fontSize: '0.9rem', marginBottom: '0.5rem', fontWeight: 700 }}>Risky Extensions:</h4>
                            <ul style={{ paddingLeft: '1.5rem', listStyle: 'disc', color: 'hsl(var(--text-primary))' }}>
                                {extensions
                                    .filter((e: any) => e && (e.risk_level === 'CRITICAL' || e.risk_level === 'HIGH'))
                                    .map((e: any) => (
                                        <li key={e.id || Math.random()} style={{ marginBottom: '0.25rem' }}>
                                            <strong>{e.name || 'Unknown'}</strong> ({e.browser || 'Unknown'})
                                        </li>
                                    ))
                                }
                            </ul>
                        </div>
                    </div>
                </div>
            )}

            {/* Extensions List */}
            <Card title={`Extensions (${extensions.length})`}>
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                    {extensions.map((ext: any, idx: number) => {
                        if (!ext) return null;
                        const riskFactors = Array.isArray(ext.risk_factors) ? ext.risk_factors : [];
                        const rawRemediation = (typeof ext.remediation === 'object' && ext.remediation !== null) ? ext.remediation : {};
                        
                        // Generate default remediation if missing, based on risk level
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
                                case 'LOW':
                                default:
                                    return {
                                        action: 'KEEP',
                                        description: 'This extension appears safe but should be kept up to date.',
                                        steps: []
                                    };
                            }
                        };

                        const defaults = getDefaultRemediation(ext.risk_level);

                        const remediation = { 
                            action: rawRemediation.action || defaults.action, 
                            description: rawRemediation.description || defaults.description, 
                            steps: (Array.isArray(rawRemediation.steps) && rawRemediation.steps.length > 0) 
                                ? rawRemediation.steps 
                                : defaults.steps 
                        };
                        const isExpanded = expandedExt === ext.id;
                        const isExpandable = ext.risk_level === 'CRITICAL' || ext.risk_level === 'HIGH';
                        
                        return (
                        <div key={idx} style={{
                            borderBottom: idx < extensions.length - 1 ? '1px solid hsl(var(--border-color))' : 'none',
                            background: isExpanded ? 'hsl(var(--bg-tertiary))' : 'transparent',
                            transition: 'background 0.2s ease'
                        }}>
                            <div 
                                onClick={() => isExpandable && setExpandedExt(isExpanded ? null : ext.id)}
                                style={{
                                    padding: '1rem',
                                    display: 'grid',
                                    gridTemplateColumns: 'minmax(200px, 2fr) 100px 100px 100px 40px',
                                    gap: '1rem',
                                    alignItems: 'center',
                                    cursor: isExpandable ? 'pointer' : 'default'
                                }}
                            >
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                    <div style={{
                                        padding: '0.5rem',
                                        background: 'hsl(var(--bg-secondary))',
                                        borderRadius: 'var(--radius-md)',
                                        display: 'flex',
                                        alignItems: 'center',
                                        justifyContent: 'center'
                                    }}>
                                       <span style={{ fontSize: '1.25rem' }}>🧩</span>
                                    </div>
                                    <div>
                                        <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: 'hsl(var(--text-primary))', marginBottom: '0.125rem' }}>
                                            {ext.name || 'Unknown Extension'}
                                        </h4>
                                        <p style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))' }}>
                                            {ext.browser || 'Unknown'} • v{ext.version || '0.0'}
                                        </p>
                                    </div>
                                </div>

                                <div style={{ textAlign: 'center' }}>
                                    <span style={{ 
                                        padding: '0.25rem 0.625rem',
                                        borderRadius: 'var(--radius-full)',
                                        background: getRiskBg(ext.risk_level),
                                        color: getRiskColor(ext.risk_level),
                                        fontSize: '0.7rem',
                                        fontWeight: 700,
                                        border: `1px solid ${getRiskColor(ext.risk_level)}40`
                                    }}>
                                        {ext.risk_level || 'UNKNOWN'}
                                    </span>
                                </div>

                                <div style={{ textAlign: 'center' }}>
                                    <span style={{ fontSize: '0.875rem', fontWeight: 700, color: getRiskColor(ext.risk_level) }}>
                                        {ext.risk_score || 0}/100
                                    </span>
                                </div>
                                
                                <div>
                                    {remediation.action === 'REMOVE' && (
                                        <span style={{ color: 'hsl(var(--color-error))', fontWeight: 700, fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                                            <Trash2 size={12} /> REMOVE
                                        </span>
                                    )}
                                </div>
                            </div>
                            
                            {/* Expanded Details */}
                            {isExpanded && (
                                <div style={{ padding: '1rem', borderTop: '1px solid hsl(var(--border-color))' }}>
                                    {/* Remediation / Action Section */}
                                    <div style={{ 
                                        padding: '1rem', 
                                        background: remediation.action === 'REMOVE' ? 'hsla(var(--color-error), 0.1)' : 'hsla(var(--color-info), 0.1)',
                                        borderRadius: 'var(--radius-md)',
                                        marginBottom: '1.5rem',
                                        border: `1px solid ${remediation.action === 'REMOVE' ? 'hsla(var(--color-error), 0.3)' : 'hsla(var(--color-info), 0.3)'}`
                                    }}>
                                        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
                                            <div style={{ 
                                                padding: '0.5rem', 
                                                background: remediation.action === 'REMOVE' ? 'hsl(var(--color-error))' : 'hsl(var(--color-info))',
                                                borderRadius: '50%',
                                                color: 'white'
                                            }}>
                                                {remediation.action === 'REMOVE' ? <Trash2 size={20} /> : <CheckCircle size={20} />}
                                            </div>
                                            <div>
                                                <h4 style={{ 
                                                    fontSize: '1rem', 
                                                    fontWeight: 700, 
                                                    color: remediation.action === 'REMOVE' ? 'hsl(var(--color-error))' : 'hsl(var(--color-info))',
                                                    marginBottom: '0.25rem'
                                                }}>
                                                    Recommended Action: {remediation.action || 'REVIEW'}
                                                </h4>
                                                <p style={{ fontSize: '0.875rem', marginBottom: '0.75rem', color: 'hsl(var(--text-primary))' }}>
                                                    {remediation.description || 'No specific remediation guidance available.'}
                                                </p>
                                                
                                                {remediation.steps && remediation.steps.length > 0 && (
                                                    <div style={{ marginTop: '0.5rem' }}>
                                                        <p style={{ fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase', color: 'hsl(var(--text-secondary))', marginBottom: '0.25rem' }}>
                                                            Removal Steps:
                                                        </p>
                                                        <ol style={{ paddingLeft: '1.25rem', fontSize: '0.875rem', color: 'hsl(var(--text-secondary))' }}>
                                                            {remediation.steps.map((step: string, sIdx: number) => (
                                                                <li key={sIdx}>{step}</li>
                                                            ))}
                                                        </ol>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    </div>

                                    {/* Metadata */}
                                    <div style={{ 
                                        display: 'grid', 
                                        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
                                        gap: '1rem',
                                        marginBottom: '1rem'
                                    }}>
                                        <div>
                                            <span style={{ fontSize: '0.7rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>ID</span>
                                            <p style={{ fontSize: '0.8rem', fontFamily: 'monospace', wordBreak: 'break-all' }}>{ext.id}</p>
                                        </div>
                                        {ext.author && (
                                            <div>
                                                <span style={{ fontSize: '0.7rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Author</span>
                                                <p style={{ fontSize: '0.875rem' }}>{ext.author}</p>
                                            </div>
                                        )}
                                        <div>
                                            <span style={{ fontSize: '0.7rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Manifest Version</span>
                                            <p style={{ fontSize: '0.875rem' }}>v{ext.manifest_version}</p>
                                        </div>
                                    </div>
                                    
                                    {/* Risk Factors */}
                                    {riskFactors.length > 0 && (
                                        <div style={{ marginBottom: '1rem' }}>
                                            <h4 style={{ fontSize: '0.8rem', fontWeight: 700, marginBottom: '0.5rem', color: 'hsl(var(--color-error))' }}>
                                                Risk Factors ({riskFactors.length})
                                            </h4>
                                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                                                {riskFactors.filter((f: any) => f).map((factor: any, fIdx: number) => (
                                                    <div key={fIdx} style={{ 
                                                        padding: '0.5rem 0.75rem',
                                                        background: getRiskBg(factor.risk),
                                                        borderRadius: 'var(--radius-md)',
                                                        display: 'flex',
                                                        alignItems: 'center',
                                                        gap: '0.75rem'
                                                    }}>
                                                        <span style={{ 
                                                            padding: '0.125rem 0.5rem',
                                                            borderRadius: 'var(--radius-sm)',
                                                            background: getRiskColor(factor.risk),
                                                            color: 'white',
                                                            fontSize: '0.65rem',
                                                            fontWeight: 700
                                                        }}>
                                                            {factor.risk}
                                                        </span>
                                                        <code style={{ fontSize: '0.75rem', color: 'hsl(var(--text-primary))' }}>
                                                            {factor.permission}
                                                        </code>
                                                        <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))' }}>
                                                            — {factor.description}
                                                        </span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                        );
                    })}
                </div>
            </Card>
        </div>
    );
};

// Helper for Metadata Table
const MetadataTable = ({ data, title }: { data: Record<string, any>, title: string }) => {
    if (!data || Object.keys(data).length === 0) return null;
    
    const filteredData = Object.entries(data).filter(([_, value]) => {
        if (value === null || value === undefined) return false;
        if (value === 'None' || value === 'null') return false;
        if (typeof value === 'string' && value.trim() === '') return false;
        return true;
    });
    
    if (filteredData.length === 0) return null;
    
    return (
        <Card title={title}>
            <div style={{ overflowX: 'auto', maxHeight: '350px', overflowY: 'auto' }}>
                <table className="data-table">
                    <thead>
                        <tr>
                            <th style={{ width: '40%' }}>Tag</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        {filteredData.map(([key, value], idx) => (
                            <tr key={idx}>
                                <td style={{ fontWeight: 600 }}>{key}</td>
                                <td style={{ fontFamily: 'monospace', fontSize: '0.8rem', wordBreak: 'break-all' }}>
                                    {String(value)}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </Card>
    );
};

// Privacy Checks Helper
const privacyChecks = (result: any) => {
    const checks: Array<{ label: string; found: boolean; severity: string; detail: string }> = [];
    
    if (result.gps && Object.keys(result.gps).length > 0) {
        checks.push({ label: 'GPS Location Data', found: true, severity: 'HIGH', detail: 'File contains GPS coordinates that reveal where it was created' });
    }
    if (result.exif) {
        const exifKeys = Object.keys(result.exif).map(k => k.toLowerCase());
        if (exifKeys.some(k => k.includes('make') || k.includes('model'))) {
            checks.push({ label: 'Camera/Device Info', found: true, severity: 'MEDIUM', detail: 'Device make and model are embedded in the file' });
        }
        if (exifKeys.some(k => k.includes('software'))) {
            checks.push({ label: 'Software Info', found: true, severity: 'LOW', detail: 'Editing software information is stored in metadata' });
        }
    }
    if (result.extended_metadata) {
        const extKeys = Object.keys(result.extended_metadata).map(k => k.toLowerCase());
        if (extKeys.some(k => k.includes('author') || k.includes('creator') || k.includes('last_modified_by'))) {
            checks.push({ label: 'Author Identity', found: true, severity: 'MEDIUM', detail: 'Author name or user identity is embedded' });
        }
    }
    
    if (checks.length === 0) {
        checks.push({ label: 'No Privacy Risks', found: false, severity: 'SAFE', detail: 'No sensitive metadata detected' });
    }
    
    return checks;
};

// Render Metadata Scan Results
const renderMetadataResult = (result: any) => {
    if (!result) return <p>No result data available</p>;

    const formatBytes = (bytes: number): string => {
        if (!bytes) return 'N/A';
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    };

    const countFields = () => {
        if (!result) return 0;
        let count = 5; // base file info fields
        if (result.exif) count += Object.keys(result.exif).length;
        if (result.gps) count += Object.keys(result.gps).length;
        if (result.extended_metadata) count += Object.keys(result.extended_metadata).length;
        if (result.document_stats) count += Object.keys(result.document_stats).length;
        if (result.workbook_stats) count += Object.keys(result.workbook_stats).length;
        return count;
    };

    const privacy = privacyChecks(result);
    const hasPrivacyRisks = privacy.some(p => p.found);

    const getSeverityColor = (s: string) => {
        if (s === 'HIGH') return 'hsl(var(--color-error))';
        if (s === 'MEDIUM') return '#f97316';
        if (s === 'LOW') return 'hsl(var(--color-warning))';
        return 'hsl(var(--color-success))';
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            
             {/* Header Status */}
             <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                {hasPrivacyRisks ? 
                    <EyeOff size={24} style={{ color: '#f97316' }} /> :
                    <Eye size={24} style={{ color: 'hsl(var(--color-success))' }} />
                }
                <span style={{ fontWeight: 700, color: hasPrivacyRisks ? '#f97316' : 'hsl(var(--color-success))', fontSize: '1.25rem' }}>
                    {hasPrivacyRisks ? 'Privacy Risks Detected' : 'No Privacy Risks Found'}
                </span>
            </div>

            {/* ROW 1: File Info Summary Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '0.75rem' }}>
                <Card>
                    <div style={{ textAlign: 'center', padding: '0.5rem 0' }}>
                        <HardDrive size={20} style={{ color: 'hsl(var(--color-primary))', marginBottom: '0.25rem' }} />
                        <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Size</p>
                        <p style={{ fontSize: '1.25rem', fontWeight: 900, color: 'hsl(var(--color-primary))' }}>
                            {formatBytes(result.size_bytes)}
                        </p>
                    </div>
                </Card>
                <Card>
                    <div style={{ textAlign: 'center', padding: '0.5rem 0' }}>
                        <FileCode size={20} style={{ color: '#eab308', marginBottom: '0.25rem' }} />
                        <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Type</p>
                        <p style={{ fontSize: '0.85rem', fontWeight: 900, color: 'hsl(var(--text-primary))' }}>
                            {result.content_type?.split('/')[1]?.toUpperCase() || result.content_type || 'Unknown'}
                        </p>
                    </div>
                </Card>
                <Card>
                    <div style={{ textAlign: 'center', padding: '0.5rem 0' }}>
                        <Info size={20} style={{ color: 'hsl(var(--color-info))', marginBottom: '0.25rem' }} />
                        <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Fields</p>
                        <p style={{ fontSize: '1.25rem', fontWeight: 900, color: 'hsl(var(--color-info))' }}>
                            {countFields()}
                        </p>
                    </div>
                </Card>
                {result.is_image && result.dimensions && (
                    <Card>
                        <div style={{ textAlign: 'center', padding: '0.5rem 0' }}>
                            <Camera size={20} style={{ color: 'hsl(var(--color-secondary))', marginBottom: '0.25rem' }} />
                            <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Dimensions</p>
                            <p style={{ fontSize: '0.85rem', fontWeight: 900, color: 'hsl(var(--color-secondary))' }}>
                                {result.dimensions[0]} × {result.dimensions[1]}
                            </p>
                        </div>
                    </Card>
                )}
                {result.gps && Object.keys(result.gps).length > 0 && (
                    <Card>
                        <div style={{ textAlign: 'center', padding: '0.5rem 0' }}>
                            <MapPin size={20} style={{ color: 'hsl(var(--color-error))', marginBottom: '0.25rem' }} />
                            <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>GPS</p>
                            <p style={{ fontSize: '0.85rem', fontWeight: 900, color: 'hsl(var(--color-error))' }}>
                                Embedded
                            </p>
                        </div>
                    </Card>
                )}
            </div>

            {/* ROW 2: Privacy Risk Indicators */}
            {privacy.length > 0 && (
                <Card title="Privacy Risk Assessment">
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                        {privacy.map((check, idx) => (
                            <div key={idx} style={{
                                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                padding: '0.5rem 0.75rem',
                                background: check.found ? `${getSeverityColor(check.severity)}08` : 'hsla(var(--color-success), 0.04)',
                                borderRadius: 'var(--radius-sm)',
                                border: `1px solid ${check.found ? getSeverityColor(check.severity) + '15' : 'hsla(var(--color-success), 0.12)'}`
                            }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                    {check.found ? 
                                        <AlertTriangle size={14} style={{ color: getSeverityColor(check.severity) }} /> :
                                        <Eye size={14} style={{ color: 'hsl(var(--color-success))' }} />
                                    }
                                    <div>
                                        <p style={{ fontWeight: 700, fontSize: '0.82rem', color: check.found ? getSeverityColor(check.severity) : 'hsl(var(--color-success))' }}>
                                            {check.label}
                                        </p>
                                        <p style={{ fontSize: '0.7rem', color: 'hsl(var(--text-muted))' }}>{check.detail}</p>
                                    </div>
                                </div>
                                {check.found && (
                                    <span style={{
                                        padding: '0.15rem 0.5rem', borderRadius: 'var(--radius-full)',
                                        fontSize: '0.6rem', fontWeight: 700,
                                        background: `${getSeverityColor(check.severity)}15`,
                                        color: getSeverityColor(check.severity)
                                    }}>{check.severity}</span>
                                )}
                            </div>
                        ))}
                    </div>
                </Card>
            )}

            {/* ROW 3: File Information */}
            <Card title="File Information">
                <table className="data-table">
                    <thead><tr><th style={{ width: '35%' }}>Property</th><th>Value</th></tr></thead>
                    <tbody>
                        <tr><td style={{ fontWeight: 600 }}>Filename</td><td style={{ fontFamily: 'monospace' }}>{result.filename}</td></tr>
                        <tr><td style={{ fontWeight: 600 }}>Content Type</td><td>{result.content_type}</td></tr>
                        <tr><td style={{ fontWeight: 600 }}>File Size</td><td>{formatBytes(result.size_bytes)}</td></tr>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Created</td>
                            <td style={{ fontFamily: 'monospace' }}>
                                {typeof result.created_at === 'string' ? result.created_at : new Date(result.created_at * 1000).toLocaleString()}
                            </td>
                        </tr>
                        <tr>
                            <td style={{ fontWeight: 600 }}>Modified</td>
                            <td style={{ fontFamily: 'monospace' }}>
                                {typeof result.modified_at === 'string' ? result.modified_at : new Date(result.modified_at * 1000).toLocaleString()}
                            </td>
                        </tr>
                    </tbody>
                </table>
            </Card>

            {/* Image Details */}
            {result.is_image && (
                <Card title="Image Details">
                    <table className="data-table">
                        <thead><tr><th style={{ width: '35%' }}>Property</th><th>Value</th></tr></thead>
                        <tbody>
                            <tr><td style={{ fontWeight: 600 }}>Format</td><td>{result.format}</td></tr>
                            <tr><td style={{ fontWeight: 600 }}>Mode</td><td>{result.mode}</td></tr>
                            <tr>
                                <td style={{ fontWeight: 600 }}>Dimensions</td>
                                <td style={{ fontFamily: 'monospace', color: 'hsl(var(--color-primary))' }}>
                                    {result.dimensions?.[0]} × {result.dimensions?.[1]} px
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </Card>
            )}

            {/* Extended Metadata */}
            {result.extended_metadata && <MetadataTable data={result.extended_metadata} title="Extended Metadata" />}
            {result.document_stats && <MetadataTable data={result.document_stats} title="Document Statistics" />}
            {result.workbook_stats && <MetadataTable data={result.workbook_stats} title="Workbook Statistics" />}
            {result.image_info && <MetadataTable data={result.image_info} title="Image Attributes" />}
            {result.exif && <MetadataTable data={result.exif} title="EXIF Data" />}
            {result.gps && <MetadataTable data={result.gps} title="GPS Data" />}
        </div>
    );
};

// --- Phishing Helpers ---

const getPhishingRiskColor = (score: number) => {
    if (score >= 75) return 'hsl(0, 85%, 50%)';
    if (score >= 50) return '#f97316';
    if (score >= 30) return 'hsl(var(--color-warning))';
    if (score >= 10) return 'hsl(var(--color-info))';
    return 'hsl(var(--color-success))';
};

const getPhishingSeverityStyle = (severity: string) => {
    switch (severity) {
        case 'high': return { bg: 'hsla(0, 85%, 50%, 0.08)', color: 'hsl(0, 85%, 50%)', border: 'hsla(0, 85%, 50%, 0.25)', icon: <ShieldAlert size={16} /> };
        case 'medium': return { bg: 'hsla(40, 90%, 50%, 0.08)', color: 'hsl(40, 90%, 50%)', border: 'hsla(40, 90%, 50%, 0.25)', icon: <AlertTriangle size={16} /> };
        case 'low': return { bg: 'hsla(210, 60%, 50%, 0.08)', color: 'hsl(210, 60%, 50%)', border: 'hsla(210, 60%, 50%, 0.25)', icon: <Info size={16} /> };
        default: return { bg: 'hsla(210, 60%, 50%, 0.08)', color: 'hsl(210, 60%, 50%)', border: 'hsla(210, 60%, 50%, 0.25)', icon: <Info size={16} /> };
    }
};

const getPhishingThreatIntelBadge = (status: string) => {
    switch (status) {
        case 'MALICIOUS': case 'FLAGGED': case 'PHISHING_VERIFIED':
            return { color: 'hsl(0, 85%, 50%)', bg: 'hsla(0, 85%, 50%, 0.1)', label: status.replace('_', ' ') };
        case 'SUSPECTED':
            return { color: 'hsl(40, 90%, 50%)', bg: 'hsla(40, 90%, 50%, 0.1)', label: 'SUSPECTED' };
        case 'CLEAN': case 'NOT_FOUND':
            return { color: 'hsl(var(--color-success))', bg: 'hsla(var(--color-success), 0.1)', label: 'CLEAN' };
        case 'NO_API_KEY':
            return { color: 'hsl(var(--text-muted))', bg: 'hsl(var(--bg-secondary))', label: 'NO KEY' };
        default:
            return { color: 'hsl(var(--text-muted))', bg: 'hsl(var(--bg-secondary))', label: status || 'N/A' };
    }
};

const renderPhishingResult = (result: any) => {
    const detectedIndicators = result?.indicators?.filter((i: any) => i.detected) || [];
    const safeIndicators = result?.indicators?.filter((i: any) => !i.detected) || [];
    const highCount = detectedIndicators.filter((i: any) => i.severity === 'high').length;
    const medCount = detectedIndicators.filter((i: any) => i.severity === 'medium').length;
    const lowCount = detectedIndicators.filter((i: any) => i.severity === 'low').length;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {/* Verdict Header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                {result.is_phishing ? 
                    <ShieldAlert size={24} style={{ color: 'hsl(var(--color-error))' }} /> :
                    <ShieldCheck size={24} style={{ color: 'hsl(var(--color-success))' }} />
                }
                <span style={{ fontWeight: 700, color: result.is_phishing ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))', fontSize: '1.25rem' }}>
                    {result.verdict || (result.is_phishing ? 'Phishing Detected' : 'URL Appears Legitimate')}
                </span>
            </div>

            {/* ROW 1: Verdict + Risk Score + Stats */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem' }}>
                {/* Verdict Card */}
                <Card>
                    <div style={{ textAlign: 'center', padding: '0.75rem 0' }}>
                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Verdict</p>
                        <p style={{ fontSize: '3.5rem', fontWeight: 900, lineHeight: 1, color: result.is_phishing ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))' }}>
                            {result.is_phishing ? '⚠' : '✓'}
                        </p>
                        <p style={{ marginTop: '0.5rem', padding: '0.2rem 0.6rem', borderRadius: 'var(--radius-full)', display: 'inline-block', fontSize: '0.65rem', fontWeight: 800, background: result.is_phishing ? 'hsl(var(--color-error-light))' : 'hsl(var(--color-success-light))', color: result.is_phishing ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))' }}>
                            {result.risk_level || 'UNKNOWN'}
                        </p>
                    </div>
                </Card>

                {/* Risk Score */}
                <Card>
                    <div style={{ textAlign: 'center', padding: '0.75rem 0' }}>
                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Risk Score</p>
                        <p style={{ fontSize: '3rem', fontWeight: 900, color: getPhishingRiskColor(result.risk_score), lineHeight: 1 }}>{result.risk_score}</p>
                        <div style={{ marginTop: '0.75rem', height: '6px', borderRadius: '3px', background: 'hsl(var(--bg-secondary))', overflow: 'hidden' }}>
                            <div style={{ height: '100%', width: `${result.risk_score}%`, borderRadius: '3px', background: `linear-gradient(90deg, hsl(var(--color-success)), hsl(var(--color-warning)), hsl(var(--color-error)))` }} />
                        </div>
                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.65rem', marginTop: '0.25rem' }}>out of 100</p>
                    </div>
                </Card>

                {/* Summary Stats */}
                <Card>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: '0.5rem', marginBottom: '0.5rem' }}>
                        <div style={{ padding: '0.4rem 0.5rem', background: highCount > 0 ? 'hsla(0, 85%, 50%, 0.06)' : 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                            <p style={{ fontSize: '0.55rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>High</p>
                            <p style={{ fontSize: '1.25rem', fontWeight: 900, color: highCount > 0 ? 'hsl(0, 85%, 50%)' : 'hsl(var(--text-muted))' }}>{highCount}</p>
                        </div>
                        <div style={{ padding: '0.4rem 0.5rem', background: medCount > 0 ? 'hsla(40, 90%, 50%, 0.06)' : 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                            <p style={{ fontSize: '0.55rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Medium</p>
                            <p style={{ fontSize: '1.25rem', fontWeight: 900, color: medCount > 0 ? 'hsl(40, 90%, 50%)' : 'hsl(var(--text-muted))' }}>{medCount}</p>
                        </div>
                        <div style={{ padding: '0.4rem 0.5rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                            <p style={{ fontSize: '0.55rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Low</p>
                            <p style={{ fontSize: '1.25rem', fontWeight: 900, color: 'hsl(var(--color-info))' }}>{lowCount}</p>
                        </div>
                        <div style={{ padding: '0.4rem 0.5rem', background: 'hsla(var(--color-success), 0.06)', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                            <p style={{ fontSize: '0.55rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Passed</p>
                            <p style={{ fontSize: '1.25rem', fontWeight: 900, color: 'hsl(var(--color-success))' }}>{safeIndicators.length}</p>
                        </div>
                    </div>
                </Card>
            </div>

            {/* Critical Flags */}
            {result.flags?.length > 0 && (
                <div style={{ padding: '0.75rem 1rem', borderRadius: 'var(--radius-lg)', background: 'hsla(0, 85%, 50%, 0.06)', border: '1px solid hsla(0, 85%, 50%, 0.2)' }}>
                    <p style={{ fontWeight: 700, fontSize: '0.75rem', color: 'hsl(0, 85%, 50%)', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <AlertTriangle size={16} /> CRITICAL FLAGS ({result.flags.length})
                    </p>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                        {result.flags.map((flag: string, idx: number) => (
                            <span key={idx} style={{ padding: '0.2rem 0.5rem', borderRadius: 'var(--radius-sm)', background: 'hsla(0, 85%, 50%, 0.1)', color: 'hsl(0, 85%, 50%)', fontSize: '0.7rem', fontWeight: 600 }}>{flag}</span>
                        ))}
                    </div>
                </div>
            )}

            {/* Detected Indicators */}
            {detectedIndicators.length > 0 && (
                <Card title="Detected Threats">
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '0.5rem' }}>
                        {detectedIndicators.map((i: any, idx: number) => {
                            const style = getPhishingSeverityStyle(i.severity);
                            return (
                                <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.75rem', background: style.bg, border: `1px solid ${style.border}`, borderRadius: 'var(--radius-md)' }}>
                                    <div style={{ color: style.color }}>{style.icon}</div>
                                    <div>
                                        <p style={{ fontSize: '0.8rem', fontWeight: 700, color: 'hsl(var(--text-primary))' }}>{i.name}</p>
                                        <p style={{ fontSize: '0.7rem', color: 'hsl(var(--text-secondary))' }}>{i.description}</p>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </Card>
            )}

            {/* Domain & SSL Info Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.5rem' }}>
                <Card title="Domain Info">
                    {result.domain_info ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                             <p><strong>Domain:</strong> {result.domain}</p>
                             <p><strong>Age:</strong> {result.domain_info.age_days} days</p>
                             <p><strong>Registrar:</strong> {result.domain_info.registrar || 'Unknown'}</p>
                        </div>
                    ) : <p>No registered domain info.</p>}
                </Card>
                <Card title="SSL Certificate">
                     {result.ssl_info ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            <p><strong>Issuer:</strong> {result.ssl_info.issuer || 'N/A'}</p>
                            <p><strong>Valid:</strong> {result.ssl_info.valid ? 'Yes' : 'No'}</p>
                        </div>
                     ) : <p>No SSL info.</p>}
                </Card>
            </div>

            {/* Threat Intelligence */}
            <Card title="Threat Intelligence">
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {[
                        { name: 'URLhaus', data: result.threat_intel?.urlhaus },
                        { name: 'PhishTank', data: result.threat_intel?.phishtank },
                        { name: 'Google Safe Browsing', data: result.threat_intel?.google_safe_browsing },
                    ].map((service, idx) => {
                        const badge = getPhishingThreatIntelBadge(service.data?.status || '');
                        return (
                            <div key={idx} style={{
                                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                                padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-md)',
                                background: badge.bg, border: `1px solid ${badge.color}20`
                            }}>
                                <span style={{ fontSize: '0.78rem', fontWeight: 600 }}>{service.name}</span>
                                <span style={{ 
                                    padding: '0.15rem 0.45rem', borderRadius: 'var(--radius-sm)',
                                    fontSize: '0.6rem', fontWeight: 800, textTransform: 'uppercase',
                                    background: `${badge.color}15`, color: badge.color
                                }}>
                                    {badge.label}
                                </span>
                            </div>
                        );
                    })}
                </div>
            </Card>

            {/* Redirect Chain */}
            {result.redirect_chain?.length > 0 && (
                <Card title={`Redirect Chain (${result.redirect_chain.length} hops)`}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.4rem 0.6rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                            <Globe size={14} style={{ color: 'hsl(var(--color-primary))' }} />
                            <span style={{ fontSize: '0.72rem', fontFamily: 'monospace', wordBreak: 'break-all', color: 'hsl(var(--color-primary))' }}>{result.url}</span>
                        </div>
                        {result.redirect_chain.map((hop: any, idx: number) => (
                            <React.Fragment key={idx}>
                                <div style={{ textAlign: 'center', color: 'hsl(var(--text-muted))' }}>
                                    <ArrowRight size={14} style={{ transform: 'rotate(90deg)' }} />
                                </div>
                                <div style={{ 
                                    display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.4rem 0.6rem', borderRadius: 'var(--radius-md)',
                                    background: idx === result.redirect_chain.length - 1 ? getPhishingRiskColor(result.risk_score) + '10' : 'hsl(var(--bg-secondary))',
                                    border: idx === result.redirect_chain.length - 1 ? `1px solid ${getPhishingRiskColor(result.risk_score)}30` : 'none'
                                }}>
                                    <ExternalLink size={14} style={{ color: 'hsl(var(--text-muted))' }} />
                                    <span style={{ fontSize: '0.72rem', fontFamily: 'monospace', wordBreak: 'break-all' }}>{hop.url}</span>
                                    <span style={{ 
                                        marginLeft: 'auto', padding: '0.1rem 0.35rem', borderRadius: 'var(--radius-sm)',
                                        fontSize: '0.6rem', fontWeight: 700, background: 'hsl(var(--bg-secondary))',
                                        color: 'hsl(var(--text-muted))', flexShrink: 0
                                    }}>{hop.status}</span>
                                </div>
                            </React.Fragment>
                        ))}
                    </div>
                </Card>
            )}

            {/* Content Analysis Card */}
            {result.content_analysis && Object.keys(result.content_analysis).length > 0 && (
                <Card title="Content Analysis">
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.5rem', marginBottom: result.content_analysis.title ? '0.75rem' : '0' }}>
                        {[
                            { label: 'Forms', value: result.content_analysis.form_count, icon: <FileWarning size={14} /> },
                            { label: 'Password Fields', value: result.content_analysis.password_fields, warn: true, icon: <Lock size={14} /> },
                            { label: 'Scripts', value: result.content_analysis.script_count, icon: <Activity size={14} /> },
                            { label: 'Iframes', value: result.content_analysis.iframe_count, icon: <Globe size={14} /> },
                            { label: 'Total Links', value: result.content_analysis.total_links, icon: <Link size={14} /> },
                            { label: 'External Links', value: result.content_analysis.external_links, icon: <ExternalLink size={14} /> },
                        ].filter(s => s.value !== undefined).map((stat, idx) => (
                            <div key={idx} style={{ 
                                padding: '0.5rem 0.6rem', borderRadius: 'var(--radius-md)', textAlign: 'center',
                                background: (stat.warn && stat.value > 0) ? 'hsla(0, 85%, 50%, 0.06)' : 'hsl(var(--bg-secondary))'
                            }}>
                                <div style={{ color: 'hsl(var(--text-muted))', marginBottom: '0.15rem' }}>{stat.icon}</div>
                                <p style={{ fontSize: '0.55rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>{stat.label}</p>
                                <p style={{ fontSize: '1.1rem', fontWeight: 900, color: (stat.warn && stat.value > 0) ? 'hsl(0, 85%, 50%)' : 'hsl(var(--text-primary))' }}>{stat.value}</p>
                            </div>
                        ))}
                    </div>
                    {result.content_analysis.title && result.content_analysis.title !== 'No Title' && (
                        <div style={{ padding: '0.4rem 0.6rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                            <span style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Page Title: </span>
                            <span style={{ fontSize: '0.78rem', fontWeight: 600 }}>{result.content_analysis.title}</span>
                        </div>
                    )}
                </Card>
            )}

            {/* Security Headers Summary */}
            {result.security_headers?.details && (
                <Card title={`Security Headers (${result.security_headers.present}/${result.security_headers.total} present)`}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.35rem' }}>
                        {Object.entries(result.security_headers.details).map(([header, info]: [string, any], idx) => (
                            <div key={idx} style={{
                                display: 'flex', alignItems: 'center', gap: '0.5rem',
                                padding: '0.4rem 0.6rem', borderRadius: 'var(--radius-sm)',
                                background: info.present ? 'hsla(var(--color-success), 0.04)' : 'hsla(var(--color-error), 0.04)',
                                border: `1px solid ${info.present ? 'hsla(var(--color-success), 0.12)' : 'hsla(var(--color-error), 0.12)'}`
                            }}>
                                {info.present ? 
                                    <CheckCircle size={13} style={{ color: 'hsl(var(--color-success))', flexShrink: 0 }} /> :
                                    <XCircle size={13} style={{ color: 'hsl(var(--color-error))', flexShrink: 0 }} />
                                }
                                <span style={{ fontSize: '0.72rem', fontWeight: 600, fontFamily: 'monospace' }}>{header}</span>
                            </div>
                        ))}
                    </div>
                </Card>
            )}
        </div>
    );
};

// --- Email Header Analysis Helpers ---
const getEmailTrustColor = (score: number) => {
    if (score >= 80) return 'hsl(var(--color-success))';
    if (score >= 60) return 'hsl(var(--color-warning))';
    if (score >= 40) return '#f97316';
    return 'hsl(var(--color-error))';
};

const getEmailTrustGradeColor = (grade: string) => {
    const colors: Record<string, string> = {
        'A': 'hsl(var(--color-success))', 'B': 'hsl(160, 70%, 45%)',
        'C': 'hsl(var(--color-warning))', 'D': '#f97316', 'F': 'hsl(var(--color-error))'
    };
    return colors[grade] || 'hsl(var(--text-muted))';
};

const getAuthStatusIcon = (status: string) => {
    switch (status) {
        case 'Pass': return <CheckCircle size={20} style={{ color: 'hsl(var(--color-success))' }} />;
        case 'Fail': return <XCircle size={20} style={{ color: 'hsl(var(--color-error))' }} />;
        case 'Neutral': return <Info size={20} style={{ color: 'hsl(var(--color-warning))' }} />;
        default: return <AlertCircle size={20} style={{ color: 'hsl(var(--text-muted))' }} />;
    }
};

const getAuthStatusColors = (status: string) => {
    switch (status) {
        case 'Pass': return { bg: 'hsla(var(--color-success), 0.06)', border: 'hsla(var(--color-success), 0.2)', text: 'hsl(var(--color-success))' };
        case 'Fail': return { bg: 'hsla(var(--color-error), 0.06)', border: 'hsla(var(--color-error), 0.2)', text: 'hsl(var(--color-error))' };
        case 'Neutral': return { bg: 'hsla(var(--color-warning), 0.06)', border: 'hsla(var(--color-warning), 0.2)', text: 'hsl(var(--color-warning))' };
        default: return { bg: 'hsl(var(--bg-secondary))', border: 'hsl(var(--border-color))', text: 'hsl(var(--text-muted))' };
    }
};

const getEmailThreatStyle = (severity: string) => {
    switch (severity) {
        case 'high': return { bg: 'hsla(var(--color-error), 0.08)', border: 'hsla(var(--color-error), 0.25)', color: 'hsl(var(--color-error))', icon: <ShieldAlert size={16} /> };
        case 'medium': return { bg: 'hsla(var(--color-warning), 0.08)', border: 'hsla(var(--color-warning), 0.25)', color: 'hsl(var(--color-warning))', icon: <AlertTriangle size={16} /> };
        default: return { bg: 'hsla(210, 60%, 50%, 0.08)', border: 'hsla(210, 60%, 50%, 0.25)', color: 'hsl(210, 60%, 50%)', icon: <Info size={16} /> };
    }
};

const renderEmailHeaderResult = (result: any) => {
    const summary = result?.summary || {};
    const routing = result?.routing || [];
    const threats = result?.threats || [];
    const allHeaders = result?.headers || [];
    const trustScore = summary.trust_score ?? 50;
    const trustGrade = summary.trust_grade || 'C';

    const authItems = [
        { label: 'SPF', status: summary.spf || 'Not Found', detail: summary.spf_detail, desc: 'Sender Policy Framework — verifies the sending server is authorized' },
        { label: 'DKIM', status: summary.dkim || 'Not Found', detail: summary.dkim_detail, desc: 'DomainKeys Identified Mail — verifies message integrity' },
        { label: 'DMARC', status: summary.dmarc || 'Not Found', detail: summary.dmarc_detail, desc: 'Domain-based Message Authentication — anti-spoofing policy' },
    ];

    const formatDelay = (seconds: number | null) => {
        if (seconds === null || seconds === undefined) return null;
        if (seconds < 1) return '<1s';
        if (seconds < 60) return `${Math.round(seconds)}s`;
        if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
        return `${(seconds / 3600).toFixed(1)}h`;
    };

    const categoryLabels: Record<string, string> = {
        auth: 'Authentication', routing: 'Routing', sender: 'Sender / Recipient',
        content: 'Content', security: 'Security / Spam', general: 'General'
    };
    const categoryIcons: Record<string, React.ReactNode> = {
        auth: <Shield size={13} />, routing: <Server size={13} />, sender: <Mail size={13} />,
        content: <FileCode size={13} />, security: <ShieldAlert size={13} />, general: <Info size={13} />
    };

    const grouped: Record<string, any[]> = {};
    allHeaders.forEach((h: any) => {
        const cat = h.category || 'general';
        if (!grouped[cat]) grouped[cat] = [];
        grouped[cat].push(h);
    });

    const headerStatusIcon = (status: string) => {
        switch (status) {
            case 'safe': return <CheckCircle size={14} style={{ color: 'hsl(var(--color-success))' }} />;
            case 'danger': return <XCircle size={14} style={{ color: 'hsl(var(--color-error))' }} />;
            case 'warning': return <AlertTriangle size={14} style={{ color: 'hsl(var(--color-warning))' }} />;
            default: return <Info size={14} style={{ color: 'hsl(var(--text-muted))' }} />;
        }
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

            {/* ROW 1: Trust Score + Authentication */}
            <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr', gap: '1.5rem' }}>
                {/* Trust Score Card */}
                <Card>
                    <div style={{ textAlign: 'center', padding: '1rem 0' }}>
                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Trust Score</p>
                        <p style={{ fontSize: '4rem', fontWeight: 900, lineHeight: 1, color: getEmailTrustGradeColor(trustGrade) }}>
                            {trustGrade}
                        </p>
                        <div style={{ marginTop: '0.75rem', height: '6px', borderRadius: '3px', background: 'hsl(var(--bg-secondary))', overflow: 'hidden' }}>
                            <div style={{ height: '100%', width: `${trustScore}%`, borderRadius: '3px', background: `linear-gradient(90deg, hsl(var(--color-error)), hsl(var(--color-warning)), hsl(var(--color-success)))`, transition: 'width 0.5s ease' }} />
                        </div>
                        <p style={{ marginTop: '0.5rem', fontSize: '1.5rem', fontWeight: 800, color: getEmailTrustColor(trustScore) }}>
                            {trustScore}<span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))', fontWeight: 500 }}>/100</span>
                        </p>
                        <div style={{ marginTop: '0.75rem', display: 'flex', justifyContent: 'center', gap: '0.75rem' }}>
                            <div style={{ textAlign: 'center' }}>
                                <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Hops</p>
                                <p style={{ fontSize: '1.1rem', fontWeight: 800 }}>{summary.hops || 0}</p>
                            </div>
                            <div style={{ textAlign: 'center' }}>
                                <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Headers</p>
                                <p style={{ fontSize: '1.1rem', fontWeight: 800 }}>{result.total_headers || 0}</p>
                            </div>
                            <div style={{ textAlign: 'center' }}>
                                <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Threats</p>
                                <p style={{ fontSize: '1.1rem', fontWeight: 800, color: threats.length > 0 ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))' }}>{threats.length}</p>
                            </div>
                        </div>
                    </div>
                </Card>

                {/* Authentication Cards */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {authItems.map((auth) => {
                        const colors = getAuthStatusColors(auth.status);
                        return (
                            <div key={auth.label} style={{
                                padding: '0.85rem 1rem', borderRadius: 'var(--radius-md)',
                                background: colors.bg, border: `1px solid ${colors.border}`,
                                display: 'flex', alignItems: 'center', gap: '0.75rem'
                            }}>
                                {getAuthStatusIcon(auth.status)}
                                <div style={{ flex: 1, minWidth: 0 }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                        <span style={{ fontWeight: 800, fontSize: '0.9rem' }}>{auth.label}</span>
                                        <span style={{
                                            padding: '0.1rem 0.4rem', borderRadius: 'var(--radius-sm)',
                                            fontSize: '0.65rem', fontWeight: 800, textTransform: 'uppercase',
                                            background: `${colors.text}15`, color: colors.text
                                        }}>{auth.status}</span>
                                    </div>
                                    <p style={{ fontSize: '0.72rem', color: 'hsl(var(--text-muted))', marginTop: '0.15rem' }}>{auth.desc}</p>
                                    {auth.detail && (
                                        <p style={{ fontSize: '0.68rem', fontFamily: 'monospace', color: 'hsl(var(--text-secondary))', marginTop: '0.3rem', wordBreak: 'break-all', opacity: 0.8 }}>
                                            {auth.detail.substring(0, 150)}{auth.detail.length > 150 ? '...' : ''}
                                        </p>
                                    )}
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* ROW 2: Email Summary */}
            <Card title="Email Summary">
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '0.5rem' }}>
                    {[
                        { label: 'From', value: summary.from, icon: <Mail size={14} /> },
                        { label: 'To', value: summary.to, icon: <ArrowRight size={14} /> },
                        { label: 'Subject', value: summary.subject, icon: <FileCode size={14} /> },
                        { label: 'Date', value: summary.date, icon: <Clock size={14} /> },
                        { label: 'Return-Path', value: summary.return_path, icon: <ArrowRight size={14} /> },
                        { label: 'Message-ID', value: summary.message_id, icon: <Hash size={14} /> },
                    ].filter(item => item.value).map((item, idx) => (
                        <div key={idx} style={{
                            padding: '0.6rem 0.75rem', background: 'hsl(var(--bg-secondary))',
                            borderRadius: 'var(--radius-md)', display: 'flex', alignItems: 'flex-start', gap: '0.5rem'
                        }}>
                            <div style={{ color: 'hsl(var(--text-muted))', marginTop: '2px', flexShrink: 0 }}>{item.icon}</div>
                            <div style={{ minWidth: 0 }}>
                                <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase', fontWeight: 600 }}>{item.label}</p>
                                <p style={{ fontSize: '0.82rem', fontWeight: 600, wordBreak: 'break-all' }}>{item.value}</p>
                            </div>
                        </div>
                    ))}
                </div>
            </Card>

            {/* ROW 3: Routing Trace */}
            {routing.length > 0 && (
                <Card title={`Routing Trace — ${routing.length} Hop${routing.length !== 1 ? 's' : ''}`}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0' }}>
                        {routing.map((hop: any, idx: number) => (
                            <React.Fragment key={idx}>
                                <div style={{
                                    display: 'flex', alignItems: 'center', gap: '0.75rem',
                                    padding: '0.65rem 0.85rem',
                                    background: idx % 2 === 0 ? 'hsl(var(--bg-secondary))' : 'transparent',
                                    borderRadius: 'var(--radius-sm)'
                                }}>
                                    <div style={{
                                        width: '28px', height: '28px', borderRadius: '50%',
                                        background: hop.tls ? 'hsla(var(--color-success), 0.15)' : 'hsl(var(--bg-secondary))',
                                        border: `2px solid ${hop.tls ? 'hsl(var(--color-success))' : 'hsl(var(--border-color))'}`,
                                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                                        fontSize: '0.7rem', fontWeight: 800, flexShrink: 0,
                                        color: hop.tls ? 'hsl(var(--color-success))' : 'hsl(var(--text-muted))'
                                    }}>
                                        {hop.hop}
                                    </div>
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                                            {hop.from_host && (
                                                <span style={{ fontSize: '0.78rem', fontWeight: 600, fontFamily: 'monospace' }}>{hop.from_host}</span>
                                            )}
                                            {hop.from_host && hop.by_host && (
                                                <ArrowRight size={12} style={{ color: 'hsl(var(--text-muted))' }} />
                                            )}
                                            {hop.by_host && (
                                                <span style={{ fontSize: '0.78rem', fontWeight: 700, fontFamily: 'monospace', color: 'hsl(var(--color-primary))' }}>{hop.by_host}</span>
                                            )}
                                        </div>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.15rem', flexWrap: 'wrap' }}>
                                            {hop.ip && (
                                                <span style={{ fontSize: '0.68rem', fontFamily: 'monospace', color: 'hsl(var(--text-secondary))', padding: '0.1rem 0.3rem', background: 'hsla(var(--color-primary), 0.08)', borderRadius: 'var(--radius-sm)' }}>{hop.ip}</span>
                                            )}
                                            {hop.protocol && (
                                                <span style={{
                                                    fontSize: '0.6rem', fontWeight: 700, padding: '0.1rem 0.3rem',
                                                    borderRadius: 'var(--radius-sm)', textTransform: 'uppercase',
                                                    background: hop.tls ? 'hsla(var(--color-success), 0.1)' : 'hsla(var(--color-warning), 0.1)',
                                                    color: hop.tls ? 'hsl(var(--color-success))' : 'hsl(var(--color-warning))'
                                                }}>
                                                    {hop.protocol}
                                                </span>
                                            )}
                                            {hop.timestamp && (
                                                <span style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))' }}>
                                                    {hop.timestamp.includes('T') ? new Date(hop.timestamp).toLocaleString() : hop.timestamp}
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                </div>
                                {idx < routing.length - 1 && (
                                    <div style={{ display: 'flex', alignItems: 'center', paddingLeft: '13px', gap: '0.5rem' }}>
                                        <div style={{ width: '2px', height: '20px', background: 'hsl(var(--border-color))' }} />
                                        {routing[idx + 1]?.delay_seconds != null && (
                                            <span style={{
                                                fontSize: '0.6rem', fontWeight: 700, padding: '0.1rem 0.35rem',
                                                borderRadius: 'var(--radius-sm)',
                                                background: (routing[idx + 1].delay_seconds > 60) ? 'hsla(var(--color-warning), 0.1)' : 'hsl(var(--bg-secondary))',
                                                color: (routing[idx + 1].delay_seconds > 60) ? 'hsl(var(--color-warning))' : 'hsl(var(--text-muted))'
                                            }}>
                                                +{formatDelay(routing[idx + 1].delay_seconds)}
                                            </span>
                                        )}
                                    </div>
                                )}
                            </React.Fragment>
                        ))}
                    </div>
                    {summary.total_delay_seconds > 0 && (
                        <div style={{ marginTop: '0.75rem', padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))' }}>Total Delivery Time</span>
                            <span style={{ fontWeight: 800, fontFamily: 'monospace', fontSize: '0.85rem' }}>{formatDelay(summary.total_delay_seconds)}</span>
                        </div>
                    )}
                </Card>
            )}

            {/* ROW 4: Threat Indicators */}
            {threats.length > 0 && (
                <Card title={`Threat Indicators (${threats.length})`}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                        {threats.map((threat: any, idx: number) => {
                            const ts = getEmailThreatStyle(threat.severity);
                            return (
                                <div key={idx} style={{
                                    display: 'flex', alignItems: 'flex-start', gap: '0.6rem',
                                    padding: '0.65rem 0.85rem', borderRadius: 'var(--radius-md)',
                                    background: ts.bg, border: `1px solid ${ts.border}`
                                }}>
                                    <div style={{ color: ts.color, marginTop: '2px', flexShrink: 0 }}>{ts.icon}</div>
                                    <div style={{ flex: 1 }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                                            <span style={{ fontWeight: 700, fontSize: '0.82rem', color: ts.color }}>{threat.type.replace(/_/g, ' ')}</span>
                                            <span style={{
                                                padding: '0.08rem 0.3rem', borderRadius: 'var(--radius-sm)',
                                                fontSize: '0.58rem', fontWeight: 800, textTransform: 'uppercase',
                                                background: `${ts.color}15`, color: ts.color
                                            }}>{threat.severity}</span>
                                        </div>
                                        <p style={{ fontSize: '0.78rem', color: 'hsl(var(--text-secondary))', marginTop: '0.2rem', lineHeight: 1.4 }}>
                                            {threat.description}
                                        </p>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </Card>
            )}

            {threats.length === 0 && (
                <div style={{
                    padding: '1rem 1.5rem', background: 'hsla(var(--color-success), 0.05)',
                    border: '1px solid hsla(var(--color-success), 0.2)', borderRadius: 'var(--radius-lg)',
                    display: 'flex', alignItems: 'center', gap: '1rem'
                }}>
                    <ShieldCheck size={24} style={{ color: 'hsl(var(--color-success))' }} />
                    <div>
                        <h3 style={{ margin: 0, fontSize: '1rem', color: 'hsl(var(--color-success))' }}>No Threats Detected</h3>
                        <p style={{ margin: 0, fontSize: '0.82rem', opacity: 0.8 }}>All authentication checks passed and no suspicious patterns were found.</p>
                    </div>
                </div>
            )}

            {/* ROW 5: Parsed Headers by Category */}
            <Card title={`All Headers (${allHeaders.length})`}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    {Object.entries(grouped).map(([cat, items]) => (
                        <div key={cat}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.4rem' }}>
                                <span style={{ color: 'hsl(var(--text-muted))' }}>{categoryIcons[cat] || <Info size={13} />}</span>
                                <span style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'hsl(var(--text-muted))' }}>
                                    {categoryLabels[cat] || cat} ({items.length})
                                </span>
                            </div>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                                {items.map((h: any, i: number) => (
                                    <div key={i} style={{
                                        display: 'flex', alignItems: 'flex-start', gap: '0.5rem',
                                        padding: '0.45rem 0.65rem', borderRadius: 'var(--radius-sm)',
                                        background: h.status === 'danger' ? 'hsla(var(--color-error), 0.04)' : h.status === 'safe' ? 'hsla(var(--color-success), 0.03)' : 'transparent',
                                        border: `1px solid ${h.status === 'danger' ? 'hsla(var(--color-error), 0.12)' : h.status === 'safe' ? 'hsla(var(--color-success), 0.1)' : 'transparent'}`
                                    }}>
                                        <div style={{ marginTop: '2px', flexShrink: 0 }}>{headerStatusIcon(h.status)}</div>
                                        <div style={{ flex: 1, minWidth: 0 }}>
                                            <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem', flexWrap: 'wrap' }}>
                                                <span style={{ fontWeight: 700, fontSize: '0.78rem', fontFamily: 'monospace' }}>{h.key}</span>
                                                <span style={{ fontSize: '0.72rem', color: 'hsl(var(--text-secondary))', wordBreak: 'break-all' }}>
                                                    {h.value.substring(0, 120)}{h.value.length > 120 ? '...' : ''}
                                                </span>
                                            </div>
                                            {h.analysis && (
                                                <p style={{ fontSize: '0.7rem', color: 'hsl(var(--text-muted))', marginTop: '0.15rem', fontStyle: 'italic' }}>
                                                    {h.analysis}
                                                </p>
                                            )}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
            </Card>
        </div>
    );
};

const getPasswordScoreColor = (score: number) => {
    if (score <= 1) return 'hsl(var(--color-error))';
    if (score === 2) return '#f97316';
    if (score === 3) return 'hsl(var(--color-warning))';
    return 'hsl(var(--color-success))';
};

const getPasswordScoreLabel = (score: number) => {
    if (score <= 0) return 'Very Weak';
    if (score === 1) return 'Weak';
    if (score === 2) return 'Fair';
    if (score === 3) return 'Moderate';
    return 'Strong';
};

const getPasswordGrade = (score: number) => {
    if (score <= 0) return 'F';
    if (score === 1) return 'D';
    if (score === 2) return 'C';
    if (score === 3) return 'B';
    return 'A';
};

const renderPasswordStrengthResult = (result: any) => {
    // Determine color/grade based on score
    const scoreColor = getPasswordScoreColor(result.score);
    const grade = getPasswordGrade(result.score);
    
    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            
            {/* Breach Alert */}
            {result.breach_count > 0 ? (
                <div style={{ 
                    padding: '1.5rem', 
                    background: 'hsla(var(--color-error), 0.1)', 
                    border: '1px solid hsla(var(--color-error), 0.3)', 
                    borderRadius: 'var(--radius-lg)', 
                    display: 'flex', alignItems: 'center', gap: '1.5rem'
                }}>
                    <div style={{ 
                        width: '60px', height: '60px', borderRadius: '50%', 
                        background: 'hsla(var(--color-error), 0.2)', 
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        color: 'hsl(var(--color-error))'
                    }}>
                        <AlertTriangle size={32} />
                    </div>
                    <div>
                        <h2 style={{ margin: '0 0 0.5rem 0', color: 'hsl(var(--color-error))', fontSize: '1.5rem' }}>
                            Password Compromised!
                        </h2>
                        <p style={{ margin: 0, opacity: 0.9 }}>
                            This password has appeared in <b>{result.breach_count.toLocaleString()} known data breaches</b>. 
                            Hackers likely already have this password in their dictionaries. 
                            <b> Do not use this password anywhere.</b>
                        </p>
                    </div>
                </div>
            ) : (
                <div style={{ 
                    padding: '1rem 1.5rem', 
                    background: 'hsla(var(--color-success), 0.05)', 
                    border: '1px solid hsla(var(--color-success), 0.2)', 
                    borderRadius: 'var(--radius-lg)', 
                    display: 'flex', alignItems: 'center', gap: '1rem'
                }}>
                    <CheckCircle size={24} style={{ color: 'hsl(var(--color-success))' }} />
                    <div>
                        <h3 style={{ margin: 0, fontSize: '1rem', color: 'hsl(var(--color-success))' }}>Clean History</h3>
                        <p style={{ margin: 0, fontSize: '0.85rem', opacity: 0.8 }}>No matches found in known data breaches (HaveIBeenPwned API).</p>
                    </div>
                </div>
            )}

            {/* Verdict Header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                {result.score >= 3 ? 
                    <ShieldCheck size={24} style={{ color: 'hsl(var(--color-success))' }} /> :
                    <ShieldAlert size={24} style={{ color: scoreColor }} />
                }
                <span style={{ fontWeight: 700, color: scoreColor, fontSize: '1.25rem' }}>
                    {getPasswordScoreLabel(result.score)} Password
                </span>
            </div>

            {/* Metrics Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.5rem' }}>
                {/* Grade Card */}
                <Card>
                    <div style={{ textAlign: 'center', padding: '1rem 0' }}>
                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Strength Grade</p>
                        <p style={{ fontSize: '4rem', fontWeight: 900, lineHeight: 1, color: result.breach_count > 0 ? 'hsl(var(--color-error))' : scoreColor }}>
                            {result.breach_count > 0 ? 'F' : grade}
                        </p>
                        <div style={{ marginTop: '0.75rem', height: '6px', borderRadius: '3px', background: 'hsl(var(--bg-secondary))', overflow: 'hidden' }}>
                            <div style={{ height: '100%', width: `${(result.score / 4) * 100}%`, borderRadius: '3px', background: `linear-gradient(90deg, hsl(var(--color-error)), hsl(var(--color-warning)), hsl(var(--color-success)))` }} />
                        </div>
                    </div>
                </Card>

                {/* Score & Crack Time */}
                <Card>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '0.75rem' }}>
                        <div style={{ padding: '0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div>
                                <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Score</p>
                                <p style={{ fontSize: '1.5rem', fontWeight: 900, color: scoreColor }}>{result.score}/4</p>
                            </div>
                            <Activity size={20} style={{ color: 'hsl(var(--text-muted))' }} />
                        </div>
                        <div style={{ 
                            padding: '0.75rem', 
                            background: result.score <= 1 ? 'hsl(var(--color-error-light))' : result.score <= 2 ? 'hsl(var(--color-warning-light))' : 'hsl(var(--color-success-light))',
                            borderRadius: 'var(--radius-md)',
                            border: `1px solid ${result.score <= 1 ? 'hsla(var(--color-error), 0.2)' : result.score <= 2 ? 'hsla(var(--color-warning), 0.2)' : 'hsla(var(--color-success), 0.2)'}`,
                            display: 'flex', justifyContent: 'space-between', alignItems: 'center'
                        }}>
                            <div>
                                <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Crack Time</p>
                                <p style={{ fontSize: '1.1rem', fontWeight: 700, fontFamily: 'monospace', color: scoreColor }}>{result.crack_times_display?.offline_slow_hashing_1e4_per_second || result.crack_time_display || 'Instant'}</p>
                            </div>
                            <Clock size={20} style={{ color: scoreColor }} />
                        </div>
                    </div>
                </Card>
            </div>

            {/* Criteria Checklist (if passed) */}
            {result.criteria && result.criteria.length > 0 && (
                <Card title="Complexity Standards">
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.35rem' }}>
                        {result.criteria.map((c: any, idx: number) => (
                            <div key={idx} style={{
                                display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 0.75rem',
                                background: c.met ? 'hsla(var(--color-success), 0.04)' : 'hsla(var(--color-error), 0.04)',
                                borderRadius: 'var(--radius-sm)',
                                border: `1px solid ${c.met ? 'hsla(var(--color-success), 0.12)' : 'hsla(var(--color-error), 0.12)'}`
                            }}>
                                {c.met ? <CheckCircle size={14} style={{ color: 'hsl(var(--color-success))' }} /> : <XCircle size={14} style={{ color: 'hsl(var(--color-error))' }} />}
                                <span style={{ fontSize: '0.8rem', fontWeight: 600, color: c.met ? 'hsl(var(--color-success))' : 'hsl(var(--text-secondary))' }}>{c.label}</span>
                            </div>
                        ))}
                    </div>
                </Card>
            )}

            {/* Warnings & Suggestions */}
            {result.feedback && (result.feedback.warning || (result.feedback.suggestions && result.feedback.suggestions.length > 0)) && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {result.feedback.warning && (
                        <div style={{ 
                            padding: '0.75rem 1rem', background: 'hsl(var(--color-error-light))', 
                            borderLeft: '4px solid hsl(var(--color-error))', borderRadius: 'var(--radius-md)',
                            display: 'flex', alignItems: 'flex-start', gap: '0.5rem'
                        }}>
                            <AlertTriangle size={16} style={{ color: 'hsl(var(--color-error))', marginTop: '2px', flexShrink: 0 }} />
                            <div>
                                <p style={{ fontSize: '0.75rem', fontWeight: 700, color: 'hsl(var(--color-error))', textTransform: 'uppercase' }}>Critical Warning</p>
                                <p style={{ fontSize: '0.85rem', color: 'hsl(var(--text-primary))' }}>{result.feedback.warning}</p>
                            </div>
                        </div>
                    )}
                    {result.feedback.suggestions && result.feedback.suggestions.length > 0 && (
                        <Card title="How to Strengthen">
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                                {result.feedback.suggestions.map((s: string, i: number) => (
                                    <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', padding: '0.5rem 0.75rem', background: 'hsla(var(--color-warning), 0.05)', borderRadius: 'var(--radius-sm)', border: '1px solid hsla(var(--color-warning), 0.12)' }}>
                                        <Info size={14} style={{ color: 'hsl(var(--color-warning))', marginTop: '2px', flexShrink: 0 }} />
                                        <span style={{ fontSize: '0.82rem', color: 'hsl(var(--text-secondary))' }}>{s}</span>
                                    </div>
                                ))}
                            </div>
                        </Card>
                    )}
                </div>
            )}
        </div>
    );
};

// --- Security Headers Helpers ---
const getSecurityScoreColor = (score: number) => {
    if (score >= 80) return 'hsl(var(--color-success))';
    if (score >= 50) return 'hsl(var(--color-warning))';
    return 'hsl(var(--color-error))';
};

const getSecurityGrade = (score: number) => {
    if (score >= 90) return 'A+';
    if (score >= 80) return 'A';
    if (score >= 70) return 'B';
    if (score >= 60) return 'C';
    if (score >= 50) return 'D';
    return 'F';
};

const getSecurityStatusIcon = (status: string) => {
    switch (status) {
        case 'present': return <CheckCircle size={16} style={{ color: 'hsl(var(--color-success))' }} />;
        case 'missing': return <XCircle size={16} style={{ color: 'hsl(var(--color-error))' }} />;
        case 'weak': return <AlertTriangle size={16} style={{ color: 'hsl(var(--color-warning))' }} />;
        default: return <Info size={16} style={{ color: 'hsl(var(--color-info))' }} />;
    }
};

const renderSecurityHeadersResult = (result: any, target: string) => {
    const presentHeaders = result?.headers?.filter((h: any) => h.status === 'present') || [];
    const missingHeaders = result?.headers?.filter((h: any) => h.status === 'missing') || [];
    const weakHeaders = result?.headers?.filter((h: any) => h.status === 'weak') || [];
    const headers = result?.headers || [];

    const score = result?.score || 0;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                {score >= 70 ? 
                    <Shield size={24} style={{ color: 'hsl(var(--color-success))' }} /> :
                    <ShieldAlert size={24} style={{ color: getSecurityScoreColor(score) }} />
                }
                <span style={{ 
                    fontWeight: 700, 
                    color: getSecurityScoreColor(score),
                    fontSize: '1.25rem'
                }}>
                    {score >= 70 ? 'Well Secured' : score >= 50 ? 'Needs Improvement' : 'Poorly Secured'}
                </span>
            </div>

            {/* ROW 1: Grade + Score Bar + Stats */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem' }}>
                {/* Security Grade */}
                <Card>
                    <div style={{ textAlign: 'center', padding: '1rem 0' }}>
                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>
                            Security Grade
                        </p>
                        <p style={{ 
                            fontSize: '3.5rem', 
                            fontWeight: 900, 
                            color: getSecurityScoreColor(score),
                            lineHeight: 1
                        }}>
                            {getSecurityGrade(score)}
                        </p>
                        <p style={{ 
                            marginTop: '0.5rem',
                            padding: '0.25rem 0.75rem',
                            borderRadius: 'var(--radius-full)',
                            display: 'inline-block',
                            fontSize: '0.75rem',
                            fontWeight: 800,
                            background: `${getSecurityScoreColor(score)}15`,
                            color: getSecurityScoreColor(score)
                        }}>
                            {score >= 80 ? 'EXCELLENT' : score >= 60 ? 'FAIR' : 'POOR'}
                        </p>
                    </div>
                </Card>

                {/* Score */}
                <Card>
                    <div style={{ textAlign: 'center', padding: '1rem 0' }}>
                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>
                            Score
                        </p>
                        <p style={{ 
                            fontSize: '3rem', 
                            fontWeight: 900, 
                            color: getSecurityScoreColor(score),
                            lineHeight: 1
                        }}>
                            {score}
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
                                width: `${score}%`,
                                borderRadius: '3px',
                                background: `linear-gradient(90deg, hsl(var(--color-error)), hsl(var(--color-warning)), hsl(var(--color-success)))`,
                            }} />
                        </div>
                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', marginTop: '0.25rem' }}>out of 100</p>
                    </div>
                </Card>

                {/* Stat Grid */}
                <Card>
                    <div style={{ padding: '0.25rem' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            <div style={{ 
                                padding: '0.4rem 0.75rem',
                                background: 'hsl(var(--color-success-light))',
                                borderRadius: 'var(--radius-md)',
                                border: '1px solid hsla(var(--color-success), 0.2)',
                                display: 'flex', alignItems: 'center', justifyContent: 'space-between'
                            }}>
                                <p style={{ fontSize: '0.7rem', color: 'hsl(var(--text-secondary))', textTransform: 'uppercase', fontWeight: 600 }}>Present</p>
                                <p style={{ fontSize: '1.1rem', fontWeight: 900, color: 'hsl(var(--color-success))' }}>{result.present_count}</p>
                            </div>
                            <div style={{ 
                                padding: '0.4rem 0.75rem',
                                background: 'hsl(var(--color-error-light))',
                                borderRadius: 'var(--radius-md)',
                                border: '1px solid hsla(var(--color-error), 0.2)',
                                display: 'flex', alignItems: 'center', justifyContent: 'space-between'
                            }}>
                                <p style={{ fontSize: '0.7rem', color: 'hsl(var(--text-secondary))', textTransform: 'uppercase', fontWeight: 600 }}>Missing</p>
                                <p style={{ fontSize: '1.1rem', fontWeight: 900, color: 'hsl(var(--color-error))' }}>{result.missing_count}</p>
                            </div>
                            <div style={{ 
                                padding: '0.4rem 0.75rem',
                                background: 'hsl(var(--color-warning-light))',
                                borderRadius: 'var(--radius-md)',
                                border: '1px solid hsla(var(--color-warning), 0.2)',
                                display: 'flex', alignItems: 'center', justifyContent: 'space-between'
                            }}>
                                <p style={{ fontSize: '0.7rem', color: 'hsl(var(--text-secondary))', textTransform: 'uppercase', fontWeight: 600 }}>Weak</p>
                                <p style={{ fontSize: '1.1rem', fontWeight: 900, color: 'hsl(var(--color-warning))' }}>{weakHeaders.length}</p>
                            </div>
                        </div>
                        {/* Final URL */}
                        <div style={{ marginTop: '0.75rem', padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                            <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Final URL</p>
                            <p style={{ fontSize: '0.75rem', fontFamily: 'monospace', wordBreak: 'break-all', color: 'hsl(var(--color-primary))' }}>
                                {result.final_url || target}
                            </p>
                        </div>
                    </div>
                </Card>
            </div>

            {/* ROW 2: Header Checklist (Present vs Missing) */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem' }}>
                {/* Present Headers */}
                <Card title={`Present Headers (${presentHeaders.length})`}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                        {presentHeaders.map((h: any, idx: number) => (
                            <div key={idx} style={{ 
                                display: 'flex', 
                                alignItems: 'center', 
                                gap: '0.5rem',
                                padding: '0.5rem 0.75rem',
                                borderRadius: 'var(--radius-sm)',
                                background: 'hsla(var(--color-success), 0.04)',
                                border: '1px solid hsla(var(--color-success), 0.1)'
                            }}>
                                <CheckCircle size={14} style={{ color: 'hsl(var(--color-success))', flexShrink: 0 }} />
                                <span style={{ fontSize: '0.8rem', fontFamily: 'monospace', fontWeight: 600 }}>{h.name}</span>
                            </div>
                        ))}
                        {presentHeaders.length === 0 && (
                            <p style={{ color: 'hsl(var(--text-muted))', textAlign: 'center', padding: '1rem' }}>No headers detected</p>
                        )}
                    </div>
                </Card>

                {/* Missing Headers */}
                <Card title={`Missing Headers (${missingHeaders.length})`}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                        {missingHeaders.map((h: any, idx: number) => (
                            <div key={idx} style={{ 
                                display: 'flex', 
                                alignItems: 'center', 
                                gap: '0.5rem',
                                padding: '0.5rem 0.75rem',
                                borderRadius: 'var(--radius-sm)',
                                background: 'hsla(var(--color-error), 0.04)',
                                border: '1px solid hsla(var(--color-error), 0.1)'
                            }}>
                                <XCircle size={14} style={{ color: 'hsl(var(--color-error))', flexShrink: 0 }} />
                                <span style={{ fontSize: '0.8rem', fontFamily: 'monospace', fontWeight: 600 }}>{h.name}</span>
                            </div>
                        ))}
                        {missingHeaders.length === 0 && (
                            <p style={{ color: 'hsl(var(--text-muted))', textAlign: 'center', padding: '1rem' }}>All headers present!</p>
                        )}
                    </div>
                </Card>
            </div>

            {/* ROW 3: Full Header Analysis Table */}
            <Card title="Detailed Header Analysis">
                <div style={{ overflowX: 'auto' }}>
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th style={{ width: '40px' }}>Status</th>
                                <th>Header Name</th>
                                <th>Value</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            {headers.map((header: any, idx: number) => (
                                <tr key={idx}>
                                    <td>{getSecurityStatusIcon(header.status)}</td>
                                    <td style={{ fontWeight: 600, fontFamily: 'monospace', fontSize: '0.8rem' }}>{header.name}</td>
                                    <td style={{ 
                                        fontFamily: 'monospace', 
                                        fontSize: '0.75rem',
                                        color: header.value ? 'hsl(var(--text-primary))' : 'hsl(var(--text-muted))',
                                        maxWidth: '250px',
                                        minWidth: '150px',
                                        wordBreak: 'break-all'
                                    }}>
                                        {header.value || <em>Not set</em>}
                                    </td>
                                    <td>
                                        <p style={{ fontSize: '0.8rem', color: 'hsl(var(--text-secondary))' }}>{header.description}</p>
                                        {header.recommendation && (
                                            <div style={{ 
                                                marginTop: '0.5rem', 
                                                padding: '0.5rem 0.75rem', 
                                                background: 'hsl(var(--color-warning-light))', 
                                                borderLeft: '3px solid hsl(var(--color-warning))',
                                                borderRadius: 'var(--radius-sm)',
                                                fontSize: '0.7rem',
                                                color: 'hsl(var(--color-warning))',
                                                fontWeight: 600
                                            }}>
                                                💡 {header.recommendation}
                                            </div>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </Card>
        </div>
    );
};
    
// --- Code Scanner Helpers ---
const codeSeverityStyles: Record<string, { bg: string; color: string; border: string; icon: React.ReactNode }> = {
    CRITICAL: {
        bg: 'hsla(0, 85%, 50%, 0.08)', color: 'hsl(0, 85%, 50%)',
        border: 'hsla(0, 85%, 50%, 0.25)', icon: <ShieldAlert size={16} />
    },
    HIGH: {
        bg: 'hsla(15, 90%, 55%, 0.08)', color: 'hsl(15, 90%, 55%)',
        border: 'hsla(15, 90%, 55%, 0.25)', icon: <AlertTriangle size={16} />
    },
    MEDIUM: {
        bg: 'hsla(40, 90%, 50%, 0.08)', color: 'hsl(40, 90%, 50%)',
        border: 'hsla(40, 90%, 50%, 0.25)', icon: <Info size={16} />
    },
    LOW: {
        bg: 'hsla(210, 60%, 50%, 0.08)', color: 'hsl(210, 60%, 50%)',
        border: 'hsla(210, 60%, 50%, 0.25)', icon: <Activity size={16} />
    },
    INFO: {
        bg: 'hsla(220, 50%, 50%, 0.06)', color: 'hsl(220, 50%, 50%)',
        border: 'hsla(220, 50%, 50%, 0.2)', icon: <Info size={16} />
    }
};

const codeGradeColors: Record<string, string> = {
    A: 'hsl(var(--color-success))',
    B: 'hsl(160, 70%, 45%)',
    C: 'hsl(var(--color-warning))',
    D: 'hsl(30, 90%, 50%)',
    F: 'hsl(var(--color-error))',
};

const codeCategoryLabels: Record<string, string> = {
    injection: 'Injection', xss: 'XSS', auth: 'Authentication',
    crypto: 'Cryptography', secrets: 'Secrets & Keys',
    error_handling: 'Error Handling', input_validation: 'Input Validation',
    file_ops: 'File Operations', network: 'Network Security',
    quality: 'Code Quality',
};

const codeCategoryIcons: Record<string, React.ReactNode> = {
    injection: <Terminal size={13} />, xss: <Code size={13} />,
    auth: <Shield size={13} />, crypto: <Hash size={13} />,
    secrets: <ShieldAlert size={13} />, error_handling: <XCircle size={13} />,
    input_validation: <CheckCircle size={13} />, file_ops: <FileCode size={13} />,
    network: <ExternalLink size={13} />, quality: <BarChart3 size={13} />,
};

const RenderCodeScanResult = ({ result }: { result: any }) => {
    const [expandedVulns, setExpandedVulns] = useState<Set<number>>(new Set());
    const [severityFilter, setSeverityFilter] = useState<string | null>(null);

    const toggleVuln = (idx: number) => {
        setExpandedVulns(prev => {
            const next = new Set(prev);
            next.has(idx) ? next.delete(idx) : next.add(idx);
            return next;
        });
    };

    const vulns = result?.vulnerabilities || [];
    const summary = result?.summary || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const totalIssues = vulns.length;

    const filteredVulns = severityFilter
        ? vulns.filter((v: any) => v.severity === severityFilter)
        : vulns;

    // Group vulns by category
    const groupedByCategory: Record<string, any[]> = {};
    vulns.forEach((v: any) => {
        const cat = v.category || 'other';
        if (!groupedByCategory[cat]) groupedByCategory[cat] = [];
        groupedByCategory[cat].push(v);
    });

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Grade + Risk Score + Info Row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
                <Card>
                    <div style={{ textAlign: 'center', padding: '0.75rem 0' }}>
                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.6rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.35rem' }}>
                            Grade
                        </p>
                        <p style={{
                            fontSize: '3.5rem', fontWeight: 900, lineHeight: 1,
                            color: codeGradeColors[result.grade] || 'hsl(var(--text-primary))',
                        }}>
                            {result.grade}
                        </p>
                        <p style={{
                            marginTop: '0.5rem', padding: '0.15rem 0.5rem', borderRadius: 'var(--radius-full)',
                            display: 'inline-block', fontSize: '0.6rem', fontWeight: 800,
                            background: totalIssues === 0 ? 'hsl(var(--color-success-light))' : 'hsl(var(--color-error-light))',
                            color: totalIssues === 0 ? 'hsl(var(--color-success))' : 'hsl(var(--color-error))'
                        }}>
                            {result.risk_level}
                        </p>
                    </div>
                </Card>

                <Card>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', marginBottom: '0.75rem' }}>
                        <div>
                            <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Risk Score</p>
                            <p style={{ fontSize: '2rem', fontWeight: 900, color: codeGradeColors[result.grade] || 'hsl(var(--text-primary))', lineHeight: 1.2 }}>
                                {result.risk_score}<span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))', fontWeight: 500 }}>/100</span>
                            </p>
                        </div>
                        <div style={{ flex: 1 }}>
                            <div style={{ height: '8px', borderRadius: '4px', background: 'hsl(var(--bg-secondary))', overflow: 'hidden' }}>
                                <div style={{
                                    height: '100%', width: `${result.risk_score}%`, borderRadius: '4px',
                                    background: `linear-gradient(90deg, hsl(var(--color-success)), hsl(var(--color-warning)), hsl(var(--color-error)))`,
                                }} />
                            </div>
                        </div>
                    </div>
                    {/* File Info */}
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.5rem' }}>
                        {[
                            { label: 'Language', value: result.language },
                            { label: 'Lines', value: result.lines_analyzed },
                            { label: 'Issues', value: totalIssues },
                            { label: 'Functions', value: result.metrics?.functions || '-' },
                        ].map((m, i) => (
                            <div key={i} style={{ padding: '0.35rem 0.5rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-sm)', textAlign: 'center' }}>
                                <p style={{ fontSize: '0.5rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>{m.label}</p>
                                <p style={{ fontSize: '0.82rem', fontWeight: 800, textTransform: 'capitalize' }}>{m.value}</p>
                            </div>
                        ))}
                    </div>
                </Card>
            </div>

            {/* Severity Breakdown — clickable as filter */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '0.5rem' }}>
                {[
                    { key: 'CRITICAL', label: 'Critical', count: summary.critical, color: 'hsl(0, 85%, 50%)', bg: 'hsla(0, 85%, 50%, 0.06)' },
                    { key: 'HIGH', label: 'High', count: summary.high, color: 'hsl(15, 90%, 55%)', bg: 'hsla(15, 90%, 55%, 0.06)' },
                    { key: 'MEDIUM', label: 'Medium', count: summary.medium, color: 'hsl(40, 90%, 50%)', bg: 'hsla(40, 90%, 50%, 0.06)' },
                    { key: 'LOW', label: 'Low', count: summary.low, color: 'hsl(210, 60%, 50%)', bg: 'hsla(210, 60%, 50%, 0.06)' },
                    { key: 'INFO', label: 'Info', count: summary.info, color: 'hsl(220, 50%, 50%)', bg: 'hsla(220, 50%, 50%, 0.06)' },
                ].map((s) => (
                    <div
                        key={s.key}
                        onClick={() => setSeverityFilter(severityFilter === s.key ? null : s.key)}
                        style={{
                            padding: '0.6rem', borderRadius: 'var(--radius-md)', textAlign: 'center',
                            background: s.count > 0 ? s.bg : 'hsl(var(--bg-secondary))',
                            border: severityFilter === s.key
                                ? `2px solid ${s.color}`
                                : s.count > 0 ? `1px solid ${s.color}30` : '1px solid transparent',
                            cursor: s.count > 0 ? 'pointer' : 'default',
                            transition: 'all 0.2s',
                            opacity: severityFilter && severityFilter !== s.key ? 0.5 : 1,
                        }}
                    >
                        <p style={{ fontSize: '0.55rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{s.label}</p>
                        <p style={{ fontSize: '1.4rem', fontWeight: 900, color: s.count > 0 ? s.color : 'hsl(var(--text-muted))' }}>{s.count}</p>
                    </div>
                ))}
            </div>

            {/* Vulnerabilities — FULL WIDTH */}
            {totalIssues > 0 && (
                <Card title={`Vulnerabilities (${severityFilter ? `${filteredVulns.length} of ${totalIssues} — ${severityFilter}` : totalIssues})`}>
                    {severityFilter && (
                        <div style={{ marginBottom: '0.6rem' }}>
                            <button onClick={() => setSeverityFilter(null)} style={{
                                padding: '0.2rem 0.5rem', fontSize: '0.65rem', fontWeight: 600,
                                border: '1px solid hsl(var(--border-color))', borderRadius: 'var(--radius-sm)',
                                background: 'hsl(var(--bg-secondary))', color: 'hsl(var(--text-secondary))',
                                cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.3rem'
                            }}>
                                <XCircle size={12} /> Clear Filter
                            </button>
                        </div>
                    )}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                        {filteredVulns.map((vuln: any) => {
                            const style = codeSeverityStyles[vuln.severity] || codeSeverityStyles.LOW;
                            const realIdx = vulns.indexOf(vuln);
                            const expanded = expandedVulns.has(realIdx);
                            return (
                                <div key={realIdx} style={{
                                    background: style.bg, borderRadius: 'var(--radius-md)',
                                    border: `1px solid ${style.border}`, overflow: 'hidden',
                                    cursor: 'pointer', transition: 'all 0.2s'
                                }} onClick={() => toggleVuln(realIdx)}>
                                    {/* Header */}
                                    <div style={{
                                        display: 'flex', alignItems: 'center', gap: '0.5rem',
                                        padding: '0.6rem 0.85rem',
                                    }}>
                                        <div style={{ color: style.color, flexShrink: 0 }}>{style.icon}</div>
                                        <div style={{ flex: 1, minWidth: 0 }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                                                <span style={{ fontWeight: 700, fontSize: '0.82rem', color: style.color }}>{vuln.type}</span>
                                                {vuln.line > 0 && (
                                                    <span style={{
                                                        padding: '0.1rem 0.35rem', borderRadius: 'var(--radius-sm)',
                                                        fontSize: '0.65rem', fontWeight: 700, fontFamily: 'monospace',
                                                        background: 'hsl(var(--bg-secondary))', color: 'hsl(var(--color-primary))'
                                                    }}>L{vuln.line}</span>
                                                )}
                                                {vuln.cwe_id && (
                                                    <span style={{
                                                        padding: '0.1rem 0.35rem', borderRadius: 'var(--radius-sm)',
                                                        fontSize: '0.6rem', fontWeight: 700, fontFamily: 'monospace',
                                                        background: 'hsla(var(--color-primary), 0.1)', color: 'hsl(var(--color-primary))'
                                                    }}>{vuln.cwe_id}</span>
                                                )}
                                            </div>
                                            {!expanded && (
                                                <p style={{ fontSize: '0.72rem', color: 'hsl(var(--text-secondary))', marginTop: '0.15rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                                    {vuln.description}
                                                </p>
                                            )}
                                        </div>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexShrink: 0 }}>
                                            {vuln.category && (
                                                <span style={{
                                                    display: 'flex', alignItems: 'center', gap: '0.25rem',
                                                    padding: '0.12rem 0.4rem', borderRadius: 'var(--radius-sm)',
                                                    fontSize: '0.6rem', fontWeight: 600,
                                                    background: 'hsl(var(--bg-secondary))', color: 'hsl(var(--text-muted))'
                                                }}>
                                                    {codeCategoryIcons[vuln.category]}
                                                    {codeCategoryLabels[vuln.category] || vuln.category}
                                                </span>
                                            )}
                                            <span style={{
                                                padding: '0.12rem 0.4rem', borderRadius: 'var(--radius-sm)',
                                                fontSize: '0.6rem', fontWeight: 800, textTransform: 'uppercase',
                                                background: `${style.color}15`, color: style.color
                                            }}>{vuln.severity}</span>
                                            <ChevronDown size={14} style={{
                                                color: 'hsl(var(--text-muted))', transition: 'transform 0.2s',
                                                transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)'
                                            }} />
                                        </div>
                                    </div>

                                    {/* Expanded Details */}
                                    {expanded && (
                                        <div style={{
                                            padding: '0 0.85rem 0.7rem', borderTop: `1px solid ${style.border}`,
                                            paddingTop: '0.6rem'
                                        }}>
                                            <p style={{ fontSize: '0.78rem', color: 'hsl(var(--text-secondary))', marginBottom: '0.6rem', lineHeight: 1.5 }}>
                                                {vuln.description}
                                            </p>
                                            {vuln.code_snippet && (
                                                <div style={{
                                                    padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)',
                                                    background: 'hsl(var(--bg-primary))', fontFamily: 'monospace',
                                                    fontSize: '0.75rem', marginBottom: '0.6rem',
                                                    border: '1px solid hsl(var(--border-color))',
                                                    whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                                                    lineHeight: 1.5
                                                }}>
                                                    {vuln.code_snippet}
                                                </div>
                                            )}
                                            {vuln.fix_suggestion && (
                                                <div style={{
                                                    display: 'flex', alignItems: 'flex-start', gap: '0.4rem',
                                                    padding: '0.45rem 0.6rem', borderRadius: 'var(--radius-sm)',
                                                    background: 'hsla(var(--color-success), 0.06)',
                                                    border: '1px solid hsla(var(--color-success), 0.15)'
                                                }}>
                                                    <Lightbulb size={14} style={{ color: 'hsl(var(--color-success))', marginTop: '2px', flexShrink: 0 }} />
                                                    <span style={{ fontSize: '0.72rem', color: 'hsl(var(--color-success))', lineHeight: 1.4 }}>
                                                        {vuln.fix_suggestion}
                                                    </span>
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                    </div>
                </Card>
            )}

            {/* Clean Code */}
            {totalIssues === 0 && (
                <Card>
                    <div style={{ textAlign: 'center', padding: '2rem' }}>
                        <ShieldCheck size={48} style={{ color: 'hsl(var(--color-success))', marginBottom: '0.75rem' }} />
                        <p style={{ fontWeight: 700, fontSize: '1.1rem', color: 'hsl(var(--color-success))', marginBottom: '0.25rem' }}>
                            No Vulnerabilities Detected
                        </p>
                        <p style={{ fontSize: '0.78rem', color: 'hsl(var(--text-muted))' }}>
                            {result.lines_analyzed} lines of {result.language} analyzed — code appears secure
                        </p>
                    </div>
                </Card>
            )}

            {/* Category Breakdown */}
            {Object.keys(groupedByCategory).length > 1 && (
                <Card title="By Category">
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.4rem' }}>
                        {Object.entries(groupedByCategory).map(([cat, items]) => (
                            <div key={cat} style={{
                                display: 'flex', alignItems: 'center', gap: '0.5rem',
                                padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)',
                                background: 'hsl(var(--bg-secondary))'
                            }}>
                                {codeCategoryIcons[cat] || <Bug size={13} />}
                                <span style={{ fontSize: '0.78rem', fontWeight: 600, flex: 1 }}>
                                    {codeCategoryLabels[cat] || cat}
                                </span>
                                <span style={{
                                    padding: '0.12rem 0.4rem', borderRadius: 'var(--radius-sm)',
                                    fontSize: '0.72rem', fontWeight: 800,
                                    background: 'hsla(var(--color-primary), 0.1)', color: 'hsl(var(--color-primary))'
                                }}>{items.length}</span>
                            </div>
                        ))}
                    </div>
                </Card>
            )}
        </div>
    );
};


// ─────────────────────────────────────────────────────────
// WHOIS Lookup Renderer
// ─────────────────────────────────────────────────────────
const RenderWhoisResult = ({ result }: { result: any }) => {
    const expired = result.is_expired;
    const expiring = !expired && result.days_until_expiry !== null && result.days_until_expiry < 30;
    const statusColor = expired ? 'hsl(var(--color-error))' : expiring ? 'hsl(var(--color-warning))' : 'hsl(var(--color-success))';
    const statusBg   = expired ? 'hsl(var(--color-error-light))' : expiring ? 'hsl(var(--color-warning-light))' : 'hsl(var(--color-success-light))';
    const statusLabel = expired ? 'EXPIRED' : expiring ? 'EXPIRING SOON' : 'ACTIVE';

    const infoRows = [
        { label: 'Registrar',    value: result.registrar },
        { label: 'WHOIS Server', value: result.whois_server },
        { label: 'Organization', value: result.org },
        { label: 'Country',      value: result.country },
        { label: 'State / City', value: [result.state, result.city].filter(Boolean).join(', ') || null },
        { label: 'DNSSEC',       value: result.dnssec },
        { label: 'Registrant',   value: result.name },
    ].filter(r => r.value);

    return (
        <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Stat cards */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
                <Card>
                    <div style={{ textAlign: 'center', padding: '0.75rem 0' }}>
                        <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Domain</p>
                        <p style={{ fontSize: '1.1rem', fontWeight: 800, color: 'hsl(var(--color-primary))', fontFamily: 'monospace', marginTop: '0.25rem' }}>{result.domain}</p>
                    </div>
                </Card>
                <Card>
                    <div style={{ textAlign: 'center', padding: '0.75rem 0' }}>
                        <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Expires In</p>
                        <p style={{ fontSize: '1.5rem', fontWeight: 900, color: statusColor, marginTop: '0.25rem' }}>
                            {result.days_until_expiry !== null ? `${result.days_until_expiry}d` : 'N/A'}
                        </p>
                        <span style={{ fontSize: '0.7rem', fontWeight: 700, padding: '0.2rem 0.6rem', borderRadius: 'var(--radius-full)', background: statusBg, color: statusColor }}>
                            {statusLabel}
                        </span>
                    </div>
                </Card>
                <Card>
                    <div style={{ textAlign: 'center', padding: '0.75rem 0' }}>
                        <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Name Servers</p>
                        <p style={{ fontSize: '2rem', fontWeight: 900, color: 'hsl(var(--color-info))', marginTop: '0.25rem' }}>{result.name_servers?.length || 0}</p>
                    </div>
                </Card>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <Card title="Registration Info">
                    <table className="data-table">
                        <tbody>
                            {[
                                { label: 'Created', value: result.creation_date ? new Date(result.creation_date).toLocaleDateString() : 'N/A' },
                                { label: 'Expires', value: result.expiration_date ? new Date(result.expiration_date).toLocaleDateString() : 'N/A' },
                                { label: 'Updated', value: result.updated_date ? new Date(result.updated_date).toLocaleDateString() : 'N/A' },
                                ...infoRows.map(r => ({ label: r.label, value: r.value || 'N/A' })),
                            ].map((row, i) => (
                                <tr key={i}>
                                    <td style={{ fontWeight: 600, width: '40%' }}>{row.label}</td>
                                    <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{row.value}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </Card>

                <Card title="Name Servers">
                    {result.name_servers?.length > 0 ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            {result.name_servers.map((ns: string, i: number) => (
                                <div key={i} style={{ padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', fontFamily: 'monospace', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                    <Server size={14} style={{ color: 'hsl(var(--color-info))' }} />
                                    {ns}
                                </div>
                            ))}
                        </div>
                    ) : (
                        <p style={{ color: 'hsl(var(--text-muted))', textAlign: 'center', padding: '2rem' }}>No name servers found</p>
                    )}
                </Card>
            </div>

            {result.status?.length > 0 && (
                <Card title="Domain Status Flags">
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                        {result.status.map((s: string, i: number) => (
                            <span key={i} style={{ padding: '0.2rem 0.6rem', background: 'hsla(var(--color-info), 0.1)', border: '1px solid hsla(var(--color-info), 0.2)', color: 'hsl(var(--color-info))', borderRadius: 'var(--radius-sm)', fontSize: '0.7rem', fontWeight: 600, fontFamily: 'monospace' }}>
                                {s.split(' ')[0]}
                            </span>
                        ))}
                    </div>
                </Card>
            )}
        </div>
    );
};

// ─────────────────────────────────────────────────────────
// DNS Lookup Renderer
// ─────────────────────────────────────────────────────────
const DNS_REC_COLORS: Record<string, { bg: string; text: string }> = {
    A:     { bg: 'hsla(var(--color-primary), 0.1)',   text: 'hsl(var(--color-primary))' },
    AAAA:  { bg: 'hsla(var(--color-secondary), 0.1)', text: 'hsl(var(--color-secondary))' },
    MX:    { bg: 'hsla(var(--color-warning), 0.1)',   text: 'hsl(var(--color-warning))' },
    NS:    { bg: 'hsla(var(--color-info), 0.1)',      text: 'hsl(var(--color-info))' },
    TXT:   { bg: 'hsla(155, 60%, 40%, 0.1)',          text: 'hsl(155, 60%, 40%)' },
    CNAME: { bg: 'hsla(280, 60%, 60%, 0.1)',          text: 'hsl(280, 60%, 60%)' },
    SOA:   { bg: 'hsla(var(--color-error), 0.07)',    text: 'hsl(var(--color-error))' },
};

const RenderDnsResult = ({ result }: { result: any }) => {
    const { records, summary } = result;
    const recordTypes = Object.keys(records || {}).filter(t => records[t]?.length > 0);

    return (
        <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Summary stats */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.75rem' }}>
                {[
                    { label: 'A Records',   value: summary?.total_a_records ?? 0,   color: 'hsl(var(--color-primary))' },
                    { label: 'MX Records',  value: summary?.total_mx_records ?? 0,  color: 'hsl(var(--color-warning))' },
                    { label: 'NS Records',  value: summary?.total_ns_records ?? 0,  color: 'hsl(var(--color-info))' },
                    { label: 'TXT Records', value: summary?.total_txt_records ?? 0, color: 'hsl(155, 60%, 40%)' },
                ].map((item, i) => (
                    <Card key={i}>
                        <div style={{ textAlign: 'center', padding: '0.5rem 0' }}>
                            <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>{item.label}</p>
                            <p style={{ fontSize: '2rem', fontWeight: 900, color: item.color, marginTop: '0.25rem' }}>{item.value}</p>
                        </div>
                    </Card>
                ))}
            </div>

            {recordTypes.map(rtype => {
                const color = DNS_REC_COLORS[rtype] || { bg: 'hsl(var(--bg-secondary))', text: 'hsl(var(--text-secondary))' };
                const recs = records[rtype];
                return (
                    <Card key={rtype} title={`${rtype} — ${recs.length} record${recs.length !== 1 ? 's' : ''}`} style={{ borderLeft: `3px solid ${color.text}` }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                            {rtype === 'MX' && recs.map((r: any, i: number) => (
                                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                                    <span style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{r.exchange}</span>
                                    <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))' }}>priority {r.preference}</span>
                                </div>
                            ))}
                            {rtype === 'SOA' && recs.map((r: any, i: number) => (
                                <table key={i} className="data-table">
                                    <tbody>
                                        {[['Primary NS', r.mname], ['Responsible', r.rname], ['Serial', r.serial], ['Refresh', `${r.refresh}s`], ['Retry', `${r.retry}s`], ['Expire', `${r.expire}s`]].map(([l, v], j) => (
                                            <tr key={j}><td style={{ fontWeight: 600, width: '40%' }}>{l}</td><td style={{ fontFamily: 'monospace' }}>{v}</td></tr>
                                        ))}
                                    </tbody>
                                </table>
                            ))}
                            {rtype === 'TXT' && recs.map((r: string, i: number) => (
                                <div key={i} style={{ padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>{r}</div>
                            ))}
                            {!['MX', 'SOA', 'TXT'].includes(rtype) && recs.map((r: any, i: number) => (
                                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                                    <span style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{typeof r === 'object' ? r.value : r}</span>
                                    {typeof r === 'object' && r.ttl !== undefined && (
                                        <span style={{ fontSize: '0.7rem', color: 'hsl(var(--text-muted))' }}>TTL {r.ttl}s</span>
                                    )}
                                </div>
                            ))}
                        </div>
                    </Card>
                );
            })}

            {recordTypes.length === 0 && (
                <Card><p style={{ textAlign: 'center', padding: '2rem', color: 'hsl(var(--text-muted))' }}>No DNS records found for this domain.</p></Card>
            )}
        </div>
    );
};

// ─────────────────────────────────────────────────────────
// SSL Check Renderer
// ─────────────────────────────────────────────────────────
const gradeColorSSL: Record<string, string> = {
    A: 'hsl(var(--color-success))',
    B: 'hsl(142,70%,45%)',
    C: 'hsl(var(--color-warning))',
    D: 'hsl(30,90%,55%)',
    F: 'hsl(var(--color-error))',
};

const RenderSSLResult = ({ result }: { result: any }) => {
    if (!result) return null;

    const expiryColor = (days: number) =>
        days < 0 ? 'hsl(var(--color-error))' : days < 30 ? 'hsl(var(--color-warning))' : 'hsl(var(--color-success))';

    if (result.error && !result.cert_details) {
        return (
            <Card>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem', padding: '2rem' }}>
                    <XCircle size={48} style={{ color: 'hsl(var(--color-error))' }} />
                    <h3 style={{ fontWeight: 700, color: 'hsl(var(--color-error))' }}>SSL Check Failed</h3>
                    <p style={{ color: 'hsl(var(--text-secondary))', textAlign: 'center' }}>{result.error}</p>
                </div>
            </Card>
        );
    }

    return (
        <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Grade + Expiry Card */}
            <div style={{ display: 'grid', gridTemplateColumns: '160px 1fr', gap: '1rem' }}>
                <Card>
                    <div style={{ textAlign: 'center', padding: '1rem 0' }}>
                        <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Grade</p>
                        <p style={{ fontSize: '4rem', fontWeight: 900, lineHeight: 1, marginTop: '0.5rem', color: gradeColorSSL[result.grade] || 'hsl(var(--text-primary))' }}>{result.grade}</p>
                        <div style={{ marginTop: '0.5rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.4rem' }}>
                            {result.valid
                                ? <ShieldCheck size={16} style={{ color: 'hsl(var(--color-success))' }} />
                                : <ShieldAlert size={16} style={{ color: 'hsl(var(--color-error))' }} />}
                            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: result.valid ? 'hsl(var(--color-success))' : 'hsl(var(--color-error))' }}>
                                {result.valid ? 'VALID' : 'INVALID'}
                            </span>
                        </div>
                    </div>
                </Card>

                <Card>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                        <div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                                <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>Expiry Status</span>
                                <span style={{ fontWeight: 800, color: expiryColor(result.days_remaining ?? 0) }}>
                                    {result.days_remaining !== null ? `${result.days_remaining} days remaining` : 'Unknown'}
                                </span>
                            </div>
                            <div style={{ height: '8px', background: 'hsl(var(--bg-tertiary))', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
                                <div style={{ height: '100%', width: `${Math.min(100, Math.max(0, (result.days_remaining ?? 0) / 365 * 100))}%`, background: expiryColor(result.days_remaining ?? 0), borderRadius: 'var(--radius-full)', transition: 'width 0.5s ease' }} />
                            </div>
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                            {[
                                { label: 'Issued To', value: result.cert_details?.issued_to_cn },
                                { label: 'Issued By', value: result.cert_details?.issued_by_cn },
                                { label: 'Valid From', value: result.cert_details?.not_before ? new Date(result.cert_details.not_before).toLocaleDateString() : 'N/A' },
                                { label: 'Valid Until', value: result.cert_details?.not_after ? new Date(result.cert_details.not_after).toLocaleDateString() : 'N/A' },
                            ].map((item, i) => (
                                <div key={i} style={{ padding: '0.4rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                                    <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>{item.label}</p>
                                    <p style={{ fontSize: '0.8rem', fontWeight: 600, fontFamily: 'monospace' }}>{item.value || 'N/A'}</p>
                                </div>
                            ))}
                        </div>
                    </div>
                </Card>
            </div>

            {/* Certificate Details */}
            <Card title="Certificate Details">
                <table className="data-table">
                    <tbody>
                        {[
                            { label: 'Subject Org',    value: result.cert_details?.issued_to_org },
                            { label: 'CA Organization', value: result.cert_details?.issued_by_org },
                            { label: 'Algorithm',       value: result.cert_details?.signature_algorithm },
                            { label: 'Version',         value: result.cert_details?.version },
                            { label: 'Serial Number',   value: result.cert_details?.serial_number },
                            { label: 'SAN Count',       value: String(result.cert_details?.san_count ?? 0) },
                        ].map((row, i) => (
                            <tr key={i}><td style={{ fontWeight: 600, width: '35%' }}>{row.label}</td><td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{row.value || 'N/A'}</td></tr>
                        ))}
                    </tbody>
                </table>
            </Card>

            {/* SANs */}
            {result.cert_details?.sans?.length > 0 && (
                <Card title={`Subject Alternative Names (${result.cert_details.san_count})`}>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                        {result.cert_details.sans.map((san: string, i: number) => (
                            <span key={i} style={{ padding: '0.2rem 0.6rem', background: 'hsl(var(--bg-secondary))', border: '1px solid hsl(var(--border-color))', borderRadius: 'var(--radius-sm)', fontSize: '0.75rem', fontFamily: 'monospace', color: san.startsWith('*.') ? 'hsl(var(--color-warning))' : 'hsl(var(--text-secondary))' }}>
                                {san}
                            </span>
                        ))}
                    </div>
                </Card>
            )}
        </div>
    );
};


const getEntropyColor = (entropy: number) => {
    if (entropy >= 7.5) return 'hsl(var(--color-error))';
    if (entropy >= 6) return 'hsl(var(--color-warning))';
    return 'hsl(var(--color-success))';
};

const getEntropyLabel = (entropy: number) => {
    if (entropy >= 7.5) return 'Very High (Encrypted/Packed)';
    if (entropy >= 6) return 'Elevated';
    if (entropy >= 4) return 'Normal';
    return 'Low';
};

const RenderRansomwareResult = ({ result }: { result: any }) => {
    const formatBytes = (bytes: number): string => {
        if (!bytes) return 'N/A';
        if (bytes < 1024) return bytes + ' bytes';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    };

    const entropy = result?.entropy || 0;
    const isDetected = result?.ransomware_detected;

    return (
        <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {/* ROW 1: Verdict + Entropy Gauge + File Info */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1.5rem' }}>
                {/* Verdict */}
                <Card>
                    <div style={{ textAlign: 'center', padding: '1rem 0' }}>
                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>
                            Verdict
                        </p>
                        <p style={{ 
                            fontSize: '3.5rem', 
                            fontWeight: 900, 
                            color: isDetected ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))',
                            lineHeight: 1
                        }}>
                            {isDetected ? '⚠' : '✓'}
                        </p>
                        <p style={{ 
                            marginTop: '0.5rem',
                            padding: '0.25rem 0.75rem',
                            borderRadius: 'var(--radius-full)',
                            display: 'inline-block',
                            fontSize: '0.75rem',
                            fontWeight: 800,
                            background: isDetected ? 'hsl(var(--color-error-light))' : 'hsl(var(--color-success-light))',
                            color: isDetected ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))'
                        }}>
                            {isDetected ? 'MALICIOUS' : 'CLEAN'}
                        </p>
                    </div>
                </Card>

                {/* Entropy Gauge */}
                <Card>
                    <div style={{ textAlign: 'center', padding: '1rem 0' }}>
                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>
                            File Entropy
                        </p>
                        <p style={{ 
                            fontSize: '2.5rem', 
                            fontWeight: 900, 
                            color: getEntropyColor(entropy),
                            lineHeight: 1
                        }}>
                            {entropy.toFixed(2)}
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
                                width: `${(entropy / 8) * 100}%`,
                                borderRadius: '3px',
                                background: `linear-gradient(90deg, hsl(var(--color-success)), hsl(var(--color-warning)), hsl(var(--color-error)))`,
                            }} />
                        </div>
                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.65rem', marginTop: '0.25rem' }}>
                            {getEntropyLabel(entropy)} · max 8.0
                        </p>
                    </div>
                </Card>

                {/* File Info */}
                <Card>
                    <div style={{ padding: '0.25rem' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                            <div style={{ 
                                padding: '0.5rem 0.75rem', 
                                background: 'hsl(var(--bg-secondary))', 
                                borderRadius: 'var(--radius-md)',
                                display: 'flex', alignItems: 'center', justifyContent: 'space-between'
                            }}>
                                <p style={{ fontSize: '0.7rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase', fontWeight: 600 }}>File Name</p>
                                <p style={{ fontSize: '0.9rem', fontWeight: 700, fontFamily: 'monospace', wordBreak: 'break-all', textAlign: 'right', maxWidth: '60%' }}>
                                    {result.filename || 'N/A'}
                                </p>
                            </div>
                            <div style={{ 
                                padding: '0.5rem 0.75rem', 
                                background: 'hsl(var(--bg-secondary))', 
                                borderRadius: 'var(--radius-md)',
                                display: 'flex', alignItems: 'center', justifyContent: 'space-between'
                            }}>
                                <p style={{ fontSize: '0.7rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase', fontWeight: 600 }}>File Size</p>
                                <p style={{ fontSize: '0.9rem', fontWeight: 700, color: 'hsl(var(--color-info))' }}>
                                    {formatBytes(result.filesize || 0)}
                                </p>
                            </div>
                            <div style={{ 
                                padding: '0.5rem 0.75rem', 
                                background: 'hsl(var(--bg-secondary))', 
                                borderRadius: 'var(--radius-md)',
                                display: 'flex', alignItems: 'center', justifyContent: 'space-between'
                            }}>
                                <p style={{ fontSize: '0.7rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase', fontWeight: 600 }}>File Type</p>
                                <p style={{ fontSize: '0.9rem', fontWeight: 600 }}>{result.filetype || 'Unknown'}</p>
                            </div>
                            <div style={{ 
                                padding: '0.5rem 0.75rem', 
                                background: 'hsl(var(--bg-secondary))', 
                                borderRadius: 'var(--radius-md)',
                                display: 'flex', alignItems: 'center', justifyContent: 'space-between'
                            }}>
                                <p style={{ fontSize: '0.7rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase', fontWeight: 600 }}>Entropy Level</p>
                                <p style={{ fontSize: '0.9rem', fontWeight: 700, color: getEntropyColor(entropy) }}>
                                    {getEntropyLabel(entropy)}
                                </p>
                            </div>
                        </div>
                        {/* Details */}
                        {result.details && (
                            <div style={{ 
                                marginTop: '0.75rem', 
                                padding: '0.6rem 0.75rem', 
                                background: isDetected ? 'hsl(var(--color-error-light))' : 'hsl(var(--color-success-light))',
                                borderRadius: 'var(--radius-md)',
                                borderLeft: `3px solid ${isDetected ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))'}`,
                                fontSize: '0.8rem',
                                color: 'hsl(var(--text-secondary))'
                            }}>
                                {result.details}
                            </div>
                        )}
                    </div>
                </Card>
            </div>

            {/* ROW 2: Entropy Explanation */}
            <Card title="Entropy Analysis">
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    <div style={{ 
                        display: 'flex', 
                        justifyContent: 'space-between',
                        padding: '0.75rem 1rem',
                        background: entropy >= 7.5 ? 'hsla(0, 85%, 50%, 0.08)' : entropy >= 6 ? 'hsla(40, 90%, 50%, 0.08)' : 'hsla(var(--color-success), 0.05)',
                        borderRadius: 'var(--radius-md)',
                        border: `1px solid ${entropy >= 7.5 ? 'hsla(0, 85%, 50%, 0.25)' : entropy >= 6 ? 'hsla(40, 90%, 50%, 0.25)' : 'hsla(var(--color-success), 0.15)'}`
                    }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <Activity size={16} style={{ color: getEntropyColor(entropy) }} />
                            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>Shannon Entropy</span>
                        </div>
                        <span style={{ fontFamily: 'monospace', fontWeight: 800, color: getEntropyColor(entropy) }}>
                            {entropy.toFixed(4)}
                        </span>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '0.5rem' }}>
                        {[
                            { range: '0 – 4.0', label: 'Low', desc: 'Plaintext / structured', color: 'hsl(var(--color-success))' },
                            { range: '4.0 – 7.0', label: 'Normal', desc: 'Mixed content / code', color: 'hsl(var(--color-warning))' },
                            { range: '7.0 – 8.0', label: 'Very High', desc: 'Encrypted / packed', color: 'hsl(var(--color-error))' },
                        ].map((item) => (
                            <div key={item.range} style={{ 
                                padding: '0.5rem 0.75rem', 
                                background: 'hsl(var(--bg-secondary))', 
                                borderRadius: 'var(--radius-md)',
                                borderTop: `2px solid ${item.color}`,
                                textAlign: 'center'
                            }}>
                                <p style={{ fontSize: '0.7rem', fontWeight: 700, color: item.color, fontFamily: 'monospace' }}>{item.range}</p>
                                <p style={{ fontSize: '0.75rem', fontWeight: 600, marginTop: '0.15rem' }}>{item.label}</p>
                                <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))' }}>{item.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </Card>
        </div>
    );
};

const getFileStatusColor = (status: string) => {
    switch(status) {
        case 'MODIFIED': case 'ERROR': case 'DIFFERENT': return 'hsl(var(--color-error))';
        case 'NEW': return 'hsl(var(--color-info))';
        case 'IDENTICAL': case 'CLEAN': return 'hsl(var(--color-success))';
        default: return 'hsl(var(--color-warning))';
    }
};

const getFileStatusBg = (status: string) => {
    switch(status) {
        case 'MODIFIED': case 'ERROR': case 'DIFFERENT': return 'hsla(var(--color-error), 0.06)';
        case 'NEW': return 'hsla(var(--color-info), 0.06)';
        case 'IDENTICAL': case 'CLEAN': return 'hsla(var(--color-success), 0.06)';
        default: return 'hsla(var(--color-warning), 0.06)';
    }
};

const getFileGradeForStatus = (status: string) => {
    switch(status) {
        case 'CLEAN': case 'IDENTICAL': return { grade: '✓', label: 'Verified' };
        case 'NEW': return { grade: 'N', label: 'New File' };
        case 'MODIFIED': return { grade: '!', label: 'Modified' };
        case 'DIFFERENT': return { grade: '≠', label: 'Different' };
        default: return { grade: '?', label: status };
    }
};

const RenderFileCompareResult = ({ result }: { result: any }) => {
    if (!result) return null;

    const formatFileBytes = (bytes: number): string => {
        if (!bytes) return 'N/A';
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    };

    return (
        <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {/* Grade + Match Stats */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem' }}>
                <Card>
                    <div style={{ textAlign: 'center', padding: '0.75rem 0' }}>
                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Result</p>
                        <p style={{ fontSize: '3.5rem', fontWeight: 900, lineHeight: 1, color: getFileStatusColor(result.status) }}>
                            {getFileGradeForStatus(result.status).grade}
                        </p>
                        <p style={{ marginTop: '0.5rem', padding: '0.15rem 0.5rem', borderRadius: 'var(--radius-full)', display: 'inline-block', fontSize: '0.65rem', fontWeight: 800, background: `${getFileStatusColor(result.status)}15`, color: getFileStatusColor(result.status) }}>
                            {getFileGradeForStatus(result.status).label}
                        </p>
                    </div>
                </Card>

                <Card>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem', marginBottom: '0.75rem' }}>
                        <div style={{ padding: '0.6rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                            <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Hash Match</p>
                            <p style={{ fontSize: '1.25rem', fontWeight: 900, color: result.hashes_match ? 'hsl(var(--color-success))' : 'hsl(var(--color-error))' }}>
                                {result.hashes_match ? '✓ YES' : '✗ NO'}
                            </p>
                        </div>
                        <div style={{ padding: '0.6rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                            <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Size Match</p>
                            <p style={{ fontSize: '1.25rem', fontWeight: 900, color: result.sizes_match ? 'hsl(var(--color-success))' : 'hsl(var(--color-warning))' }}>
                                {result.sizes_match ? '✓ YES' : '✗ NO'}
                            </p>
                        </div>
                        <div style={{ padding: '0.6rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                            <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Size Diff</p>
                            <p style={{ fontSize: '0.9rem', fontWeight: 900, color: 'hsl(var(--text-primary))' }}>
                                {result.comparison?.size_difference_bytes?.toLocaleString()} B
                            </p>
                            <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))' }}>({result.comparison?.size_difference_percent}%)</p>
                        </div>
                    </div>
                    {/* Status Message */}
                    <div style={{ padding: '0.6rem 0.75rem', borderRadius: 'var(--radius-md)', background: getFileStatusBg(result.status), border: `1px solid ${getFileStatusColor(result.status)}15` }}>
                        <p style={{ fontSize: '0.82rem', color: 'hsl(var(--text-primary))' }}>{result.details}</p>
                    </div>
                </Card>
            </div>

            {/* Side by Side */}
            <Card title="Detailed Comparison">
                <div style={{ overflowX: 'auto' }}>
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th style={{ width: '20%' }}>Property</th>
                                <th style={{ width: '40%', color: 'hsl(var(--color-primary))' }}>File 1: {result.file1?.filename}</th>
                                <th style={{ width: '40%', color: 'hsl(var(--color-secondary))' }}>File 2: {result.file2?.filename}</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td style={{ fontWeight: 600 }}>Size</td>
                                <td>{formatFileBytes(result.file1?.size_bytes)}</td>
                                <td style={{ color: !result.sizes_match ? 'hsl(var(--color-warning))' : 'inherit' }}>{formatFileBytes(result.file2?.size_bytes)}</td>
                            </tr>
                            <tr>
                                <td style={{ fontWeight: 600 }}>SHA-256</td>
                                <td style={{ fontFamily: 'monospace', fontSize: '0.68rem', wordBreak: 'break-all', color: 'hsl(var(--color-primary))' }}>{result.file1?.sha256}</td>
                                <td style={{ fontFamily: 'monospace', fontSize: '0.68rem', wordBreak: 'break-all', color: result.hashes_match ? 'hsl(var(--color-success))' : 'hsl(var(--color-error))' }}>{result.file2?.sha256}</td>
                            </tr>
                            <tr>
                                <td style={{ fontWeight: 600 }}>MD5</td>
                                <td style={{ fontFamily: 'monospace', fontSize: '0.72rem', wordBreak: 'break-all', color: 'hsl(var(--text-secondary))' }}>{result.file1?.md5}</td>
                                <td style={{ fontFamily: 'monospace', fontSize: '0.72rem', wordBreak: 'break-all', color: 'hsl(var(--text-secondary))' }}>{result.file2?.md5}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </Card>
        </div>
    );
};

export const ScanResultViewer = ({ scanType, target, result, createdAt }: ScanResultViewerProps) => {
    const getScanTypeName = (type: string): string => {
        const typeMap: Record<string, string> = {
            'URL_AGGRESSIVE_SCAN': 'URL Scan',
            'IP_COMPREHENSIVE_SCAN': 'IP Scan',
            'IP_CHECK': 'IP Check',
            'FILE_INTEGRITY': 'File Integrity',
            'FILE_COMPARE': 'File Compare',
            'METADATA_SCAN': 'Metadata',
            'EMAIL_HEADERS': 'Email Headers',
            'SECURITY_HEADERS': 'Security Headers',
            'PHISHING_CHECK': 'Phishing Check',
            'PASSWORD_STRENGTH': 'Password Strength',
            'CODE_SCAN': 'Code Scan',
            'RANSOMWARE_SCAN': 'Ransomware Scan',
            'WHOIS_LOOKUP': 'WHOIS Lookup',
            'DNS_LOOKUP': 'DNS Lookup',
            'SSL_CHECK': 'SSL Check',
        };
        return typeMap[type] || type.replace(/_/g, ' ');
    };

    const renderContent = () => {
        if (scanType.includes('IP')) {
            return renderIPScanResult(result);
        } else if (scanType.includes('URL')) {
            return renderURLScanResult(result);
        } else if (scanType.includes('FILE_INTEGRITY') || scanType.includes('INTEGRITY')) {
            return renderFileIntegrityResult(result);
        } else if (scanType.includes('FILE_COMPARE') || scanType === 'COMPARE') {
            return <RenderFileCompareResult result={result} />;
        } else if (scanType === 'BROWSER_EXTENSIONS') {
            return <RenderExtensionScanResult result={result} />;
        } else if (scanType.includes('METADATA')) {
            return renderMetadataResult(result);
        } else if (scanType.includes('EMAIL')) {
            return renderEmailHeaderResult(result);
        } else if (scanType.includes('SECURITY_HEADERS')) {
            return renderSecurityHeadersResult(result, target);
        } else if (scanType.includes('PHISHING')) {
            return renderPhishingResult(result);
        } else if (scanType.includes('PASSWORD')) {
            return renderPasswordStrengthResult(result);
        } else if (scanType.includes('CODE') || scanType === 'CODE_SCAN') {
            return <RenderCodeScanResult result={result} />;

        } else if (scanType.includes('RANSOMWARE') || scanType === 'RANSOMWARE_SCAN') {
            return <RenderRansomwareResult result={result} />;
        } else if (scanType === 'WHOIS_LOOKUP') {
            return <RenderWhoisResult result={result} />;
        } else if (scanType === 'DNS_LOOKUP') {
            return <RenderDnsResult result={result} />;
        } else if (scanType === 'SSL_CHECK') {
            return <RenderSSLResult result={result} />;
        } else {
            return renderGenericResult(result, getScanTypeName(scanType));
        }
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {/* Header Info */}
            <div style={{ 
                display: 'flex', 
                justifyContent: 'space-between', 
                alignItems: 'center',
                padding: '1rem',
                background: 'hsl(var(--bg-secondary))',
                borderRadius: 'var(--radius-md)',
                marginBottom: '0.5rem'
            }}>
                <div>
                    <p style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>
                        {getScanTypeName(scanType)}
                    </p>
                    <p style={{ fontFamily: 'monospace', fontWeight: 600, color: 'hsl(var(--color-primary))' }}>
                        {target}
                    </p>
                </div>
                <div style={{ textAlign: 'right' }}>
                    <p style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))' }}>Scanned At</p>
                    <p style={{ fontSize: '0.875rem' }}>{new Date(createdAt).toLocaleString()}</p>
                </div>
            </div>

            {/* Rendered Content */}
            {renderContent()}
        </div>
    );
};

export default ScanResultViewer;
