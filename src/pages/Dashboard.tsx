
import { useNavigate } from 'react-router-dom';

import { 
    Search, Link, FileCheck, FileCode, Shield, 
    Fish, Mail, ShieldAlert, Cpu, Bug, Download,
    ArrowRight, Activity, Zap, Database, Puzzle,
    Globe, Lock
} from 'lucide-react';

export const Dashboard = () => {
    const navigate = useNavigate();

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
