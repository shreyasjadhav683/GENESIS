import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';

import { 
    Search, Link, FileCheck, FileCode, Shield, 
    Fish, Mail, ShieldAlert, Cpu, Bug, Download,
    ArrowRight, Activity, Zap, Database, Puzzle,
    Globe, Lock, BarChart2
} from 'lucide-react';

export const Dashboard = () => {
    const navigate = useNavigate();
    
    const [insights, setInsights] = useState<any>(null);
    const [loadingInsights, setLoadingInsights] = useState(true);

    useEffect(() => {
        const fetchInsights = async () => {
            try {
                const res = await api.get('/history/insights');
                setInsights(res.data);
            } catch (err) {
                console.error("Failed to fetch insights", err);
            } finally {
                setLoadingInsights(false);
            }
        };
        fetchInsights();
    }, []);

    const features = [
        { title: "IP Scanner", desc: "Analyze IP Reputation & Threat Intelligence", icon: <Search size={24} />, path: "/ip", color: "cyan" },
        { title: "URL Scanner", desc: "Malicious Link Detection & Analysis", icon: <Link size={24} />, path: "/url", color: "blue" },
        { title: "File Integrity", desc: "SHA256 & MD5 Hash Verification", icon: <FileCheck size={24} />, path: "/files/integrity", color: "green" },
        { title: "Metadata Viewer", desc: "Extract Hidden EXIF & Document Data", icon: <FileCode size={24} />, path: "/files/metadata", color: "yellow" },
        { title: "Security Headers", desc: "Check HTTP Security Headers", icon: <Shield size={24} />, path: "/scan/security-headers", color: "purple" },
        { title: "Phishing Detector", desc: "Identify Phishing & Scam URLs", icon: <Fish size={24} />, path: "/scan/phishing", color: "pink" },
        { title: "Email Headers", desc: "Analyze Email Authentication", icon: <Mail size={24} />, path: "/scan/email-headers", color: "orange" },
        { title: "Password Strength", desc: "Entropy Analysis & Crack Time", icon: <ShieldAlert size={24} />, path: "/scan/password", color: "teal" },
        { title: "Code Scanner", desc: "Static Analysis (SAST) for Vulnerabilities", icon: <Bug size={24} />, path: "/scan/code", color: "red" },
        { title: "Ransomware Detect", desc: "Heuristic Malware Analysis", icon: <ShieldAlert size={24} />, path: "/scan/ransomware", color: "red" },
        { title: "Extension Scanner", desc: "Scan Browser Extensions for Threats", icon: <Puzzle size={24} />, path: "/scan/extensions", color: "violet" },
        { title: "WHOIS & DNS", desc: "Domain Registration & DNS Record Lookup", icon: <Globe size={24} />, path: "/whois-dns", color: "cyan" },
        { title: "SSL/TLS Checker", desc: "Certificate Validity, Expiry & Chain Info", icon: <Lock size={24} />, path: "/scan/ssl", color: "green" },
        { title: "AI Assistant", desc: "Security Policy & Threat Helper", icon: <Cpu size={24} />, path: "/ai", color: "gradient" },
        { title: "Export Reports", desc: "Download Comprehensive Scan History", icon: <Download size={24} />, path: "/reports", color: "gray" },
    ];

    return (
        <div className="flex flex-col gap-8">
            {/* Stats Section */}
            <div className="stats-grid stagger-children">
                {/* System Status */}
                <div className="stat-card" style={{ '--accent-color': 'linear-gradient(135deg, #4ade80 0%, #22c55e 100%)' } as React.CSSProperties}>
                    <div>
                        <p style={{ 
                            fontSize: '0.7rem', 
                            textTransform: 'uppercase', 
                            letterSpacing: '0.15em', 
                            color: 'hsl(var(--text-secondary))',
                            fontWeight: 600,
                            marginBottom: '0.5rem'
                        }}>
                            System Status
                        </p>
                        <p style={{ 
                            fontSize: '1.75rem', 
                            fontWeight: '900', 
                            color: '#4ade80',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.5rem'
                        }}>
                            <span className="status-dot" style={{
                                width: '10px',
                                height: '10px',
                                borderRadius: '50%',
                                background: '#4ade80',
                                boxShadow: '0 0 10px #4ade80',
                                animation: 'pulseRing 2s infinite'
                            }}></span>
                            OPERATIONAL
                        </p>
                    </div>
                    <Database size={56} className="stat-card-icon" />
                </div>

                {/* Threat Level */}
                <div className="stat-card" style={{ '--accent-color': 'var(--gradient-secondary)' } as React.CSSProperties}>
                    <div>
                        <p style={{ 
                            fontSize: '0.7rem', 
                            textTransform: 'uppercase', 
                            letterSpacing: '0.15em', 
                            color: 'hsl(var(--text-secondary))',
                            fontWeight: 600,
                            marginBottom: '0.5rem'
                        }}>
                            Threat Level
                        </p>
                        <p style={{ 
                            fontSize: '1.75rem', 
                            fontWeight: '900', 
                            color: 'hsl(var(--color-secondary))'
                        }}>
                            LOW
                        </p>
                    </div>
                    <Activity size={56} className="stat-card-icon" />
                </div>

                {/* Active Modules */}
                <div className="stat-card" style={{ '--accent-color': 'linear-gradient(135deg, #facc15 0%, #eab308 100%)' } as React.CSSProperties}>
                    <div>
                        <p style={{ 
                            fontSize: '0.7rem', 
                            textTransform: 'uppercase', 
                            letterSpacing: '0.15em', 
                            color: 'hsl(var(--text-secondary))',
                            fontWeight: 600,
                            marginBottom: '0.5rem'
                        }}>
                            Active Modules
                        </p>
                        <p style={{ 
                            fontSize: '1.75rem', 
                            fontWeight: '900', 
                            color: '#facc15',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.5rem'
                        }}>
                            <Zap size={24} className="animate-pulse" />
                            14 ONLINE
                        </p>
                    </div>
                    <Cpu size={56} className="stat-card-icon" />
                </div>
            </div>

            {/* Insights Section */}
            {!loadingInsights && insights && (
                <div style={{ marginBottom: '1rem' }}>
                    <style>{`
                        @media (max-width: 1024px) {
                            .dash-col-span-2 { grid-column: span 1 !important; }
                        }
                    `}</style>
                    <div className="section-header">
                        <h2 className="section-title">Your Activity Insights</h2>
                    </div>
                    <div className="dashboard-grid stagger-children">
                        {/* Total Scans Card */}
                        <div className="card card-gradient" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', minHeight: '160px' }}>
                            <p style={{ fontSize: '0.8rem', color: 'white', textTransform: 'uppercase', letterSpacing: '0.1em', opacity: 0.8 }}>Total Scans Performed</p>
                            <div style={{ display: 'flex', alignItems: 'flex-end', gap: '1rem', marginTop: '0.5rem' }}>
                                <span style={{ fontSize: '3.5rem', fontWeight: 900, lineHeight: 1, color: 'white', textShadow: '0 2px 10px rgba(0,0,0,0.2)' }}>
                                    {insights.total_scans}
                                </span>
                                <span style={{ paddingBottom: '0.5rem', color: 'white', fontSize: '0.9rem', opacity: 0.8, fontWeight: 600 }}>scans total</span>
                            </div>
                        </div>

                        {/* Activity Graph (Last 7 Days) */}
                        <div className="card dash-col-span-2" style={{ gridColumn: 'span 2' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                                <p style={{ fontSize: '0.8rem', color: 'hsl(var(--text-secondary))', textTransform: 'uppercase', letterSpacing: '0.1em', margin: 0 }}>Scan Activity (Last 7 Days)</p>
                                <BarChart2 size={16} style={{ color: 'hsl(var(--text-muted))' }} />
                            </div>
                            <div style={{ display: 'flex', alignItems: 'flex-end', gap: '10px', height: '100px' }}>
                                {(!insights.daily_last_7_days || insights.daily_last_7_days.length === 0) ? (
                                    <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.9rem', fontStyle: 'italic', alignSelf: 'center', margin: '0 auto' }}>No activity in the last 7 days</p>
                                ) : (
                                    insights.daily_last_7_days.map((d: any, idx: number) => {
                                        const maxScans = Math.max(...insights.daily_last_7_days.map((x: any) => x.scans), 1);
                                        const heightPct = Math.max((d.scans / maxScans) * 100, d.scans > 0 ? 5 : 0);
                                        
                                        return (
                                            <div key={idx} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '4px' }}>
                                                <span style={{ fontSize: '0.7rem', color: d.scans > 0 ? 'hsl(var(--color-primary))' : 'transparent', fontWeight: 700 }}>
                                                    {d.scans}
                                                </span>
                                                <div style={{
                                                    width: '100%',
                                                    height: `${heightPct}%`,
                                                    background: d.scans > 0 ? 'var(--gradient-primary)' : 'hsla(var(--text-muted), 0.1)',
                                                    borderRadius: '4px 4px 0 0',
                                                    transition: 'height 0.5s ease',
                                                    minHeight: d.scans === 0 ? '2px' : '0'
                                                }} />
                                                <span style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))' }}>
                                                    {d.date.slice(5)}
                                                </span>
                                            </div>
                                        );
                                    })
                                )}
                            </div>
                        </div>

                        {/* Scan Types Breakdown */}
                        <div className="card">
                            <p style={{ fontSize: '0.8rem', color: 'hsl(var(--text-secondary))', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '1rem' }}>Top Scan Types</p>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                                {(!insights.by_type || insights.by_type.length === 0) ? (
                                    <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.9rem', fontStyle: 'italic' }}>No scans yet</p>
                                ) : (
                                    insights.by_type.sort((a:any, b:any) => b.count - a.count).slice(0, 4).map((t: any, idx: number) => (
                                        <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem', background: 'hsla(var(--bg-secondary), 0.5)', borderRadius: 'var(--radius-sm)' }}>
                                            <span style={{ fontSize: '0.8rem', textTransform: 'capitalize' }}>{t.type.replace(/_/g, ' ')}</span>
                                            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'hsl(var(--color-primary))', background: 'hsla(var(--color-primary), 0.1)', padding: '0.1rem 0.5rem', borderRadius: '12px' }}>{t.count}</span>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Features Section */}
            <div>
                <div className="section-header">
                    <h2 className="section-title">Security Modules</h2>
                </div>

                <div className="dashboard-grid stagger-children">
                    {features.map((feature, idx) => (
                        <div 
                            key={idx}
                            className="feature-card"
                            onClick={() => navigate(feature.path)}
                        >
                            {/* Icon */}
                            <div className="feature-icon">
                                {feature.icon}
                            </div>

                            {/* Content */}
                            <h3 style={{ 
                                fontSize: '1.125rem', 
                                fontWeight: 700, 
                                marginBottom: '0.375rem',
                                color: 'hsl(var(--text-primary))'
                            }}>
                                {feature.title}
                            </h3>
                            <p style={{ 
                                fontSize: '0.8rem', 
                                color: 'hsl(var(--text-secondary))',
                                lineHeight: 1.5,
                                marginBottom: '1rem'
                            }}>
                                {feature.desc}
                            </p>

                            {/* Action */}
                            <div style={{ 
                                display: 'flex', 
                                alignItems: 'center', 
                                justifyContent: 'space-between',
                                marginTop: 'auto'
                            }}>
                                <span style={{ 
                                    fontSize: '0.65rem', 
                                    fontFamily: 'monospace', 
                                    color: 'hsl(var(--text-muted))',
                                    textTransform: 'uppercase',
                                    letterSpacing: '0.1em'
                                }}>
                                    v1.0
                                </span>
                                <ArrowRight size={16} style={{ color: 'hsl(var(--color-primary))' }} />
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};
