
import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { ThemeToggle } from './ThemeToggle';
import { 
    Key, Home, Search, Link, FileCheck, FileCode, 
    ShieldAlert, Bug, Download, LogOut,
    Mail, Shield, Fish, Puzzle, Sparkles, Globe, Lock, Grid
} from 'lucide-react';

import { useState } from 'react';

interface SidebarItemProps {
    to: string;
    icon: React.ReactNode | ((props: { isActive: boolean }) => React.ReactNode);
    label: string;
    onMouseEnter: (e: React.MouseEvent, label: string) => void;
    onMouseLeave: () => void;
}

const SidebarItem: React.FC<SidebarItemProps> = ({ to, icon, label, onMouseEnter, onMouseLeave }) => {
    return (
        <NavLink 
            to={to} 
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            onMouseEnter={(e) => onMouseEnter(e, label)}
            onMouseLeave={onMouseLeave}
        >
            {({ isActive }) => (
                typeof icon === 'function' ? icon({ isActive }) : icon
            )}
        </NavLink>
    );
};

export const Sidebar = () => {
    const navigate = useNavigate();
    const [tooltip, setTooltip] = useState<{ label: string; top: number } | null>(null);

    const handleMouseEnter = (e: React.MouseEvent, label: string) => {
        const rect = e.currentTarget.getBoundingClientRect();
        setTooltip({ label, top: rect.top + rect.height / 2 });
    };

    const handleMouseLeave = () => {
        setTooltip(null);
    };

    const handleLogout = () => {
        localStorage.removeItem('token');
        navigate('/login');
    };

    return (
        <aside className="sidebar">
            {/* Logo */}
            <div className="logo-container">
                <ShieldAlert size={24} />
            </div>

            {/* Navigation */}
            <nav className="nav-menu">
                <SidebarItem 
                    to="/dashboard" 
                    icon={<Home size={20} />} 
                    label="Dashboard" 
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                />
                
                <div className="sidebar-divider"></div>
                
                {/* Modules Group */}
                <div 
                    className="modules-wrapper relative"
                    style={{ display: 'flex', justifyContent: 'center', width: '100%' }}
                    onMouseEnter={() => {
                        const el = document.getElementById('modules-flyout');
                        if (el) el.style.opacity = '1';
                        if (el) el.style.visibility = 'visible';
                        if (el) el.style.pointerEvents = 'auto';
                        handleMouseLeave(); // clear tooltip if any
                    }}
                    onMouseLeave={() => {
                        const el = document.getElementById('modules-flyout');
                        if (el) el.style.opacity = '0';
                        if (el) el.style.visibility = 'hidden';
                        if (el) el.style.pointerEvents = 'none';
                    }}
                >
                    <div 
                        className="nav-item cursor-pointer"
                        onMouseEnter={(e) => handleMouseEnter(e, "Security Modules")}
                        onMouseLeave={handleMouseLeave}
                    >
                        <Grid size={20} />
                    </div>

                    {/* Flyout Menu */}
                    <div 
                        id="modules-flyout"
                        style={{
                            position: 'fixed',
                            left: '80px',
                            top: '50%',
                            transform: 'translateY(-50%)',
                            background: 'var(--glass-bg)',
                            backdropFilter: 'blur(20px)',
                            WebkitBackdropFilter: 'blur(20px)',
                            border: '1px solid hsl(var(--border-color))',
                            borderRadius: 'var(--radius-lg)',
                            padding: '1rem',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '0.25rem',
                            minWidth: '220px',
                            boxShadow: '0 10px 40px rgba(0,0,0,0.5)',
                            zIndex: 100,
                            opacity: 0,
                            visibility: 'hidden',
                            pointerEvents: 'none',
                            transition: 'all 0.2s ease-in-out',
                            maxHeight: '90vh',
                            overflowY: 'auto'
                        }}
                    >
                        <p style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.1em', color: 'hsl(var(--text-secondary))', marginBottom: '0.5rem', paddingLeft: '0.5rem' }}>Scanner Modules</p>
                        
                        {[
                            { to: "/ip", icon: <Search size={18} />, label: "IP Scanner" },
                            { to: "/url", icon: <Link size={18} />, label: "URL Scanner" },
                            { to: "/files/integrity", icon: <FileCheck size={18} />, label: "File Integrity" },
                            { to: "/files/metadata", icon: <FileCode size={18} />, label: "Metadata" },
                            { to: "/scan/email-headers", icon: <Mail size={18} />, label: "Email Analyzer" },
                            { to: "/scan/security-headers", icon: <Shield size={18} />, label: "Security Headers" },
                            { to: "/scan/phishing", icon: <Fish size={18} />, label: "Phishing Detector" },
                            { to: "/scan/password", icon: <Key size={18} />, label: "Password Strength" },
                            { to: "/scan/code", icon: <Bug size={18} />, label: "Code Scanner" },
                            { to: "/scan/ransomware", icon: <ShieldAlert size={18} />, label: "Ransomware" },
                            { to: "/scan/extensions", icon: <Puzzle size={18} />, label: "Extension Scanner" },
                            { to: "/whois-dns", icon: <Globe size={18} />, label: "WHOIS & DNS" },
                            { to: "/scan/ssl", icon: <Lock size={18} />, label: "SSL Checker" }
                        ].map((m, idx) => (
                            <NavLink 
                                key={idx} 
                                to={m.to} 
                                className={({ isActive }) => `flyout-item ${isActive ? 'active' : ''}`}
                                style={({ isActive }) => ({
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '0.75rem',
                                    padding: '0.6rem 0.75rem',
                                    textDecoration: 'none',
                                    borderRadius: 'var(--radius-sm)',
                                    color: isActive ? 'hsl(var(--color-primary))' : 'hsl(var(--text-secondary))',
                                    background: isActive ? 'hsla(var(--color-primary), 0.1)' : 'transparent',
                                    transition: 'all 0.2s ease',
                                    fontSize: '0.9rem',
                                    fontWeight: isActive ? 600 : 500
                                })}
                            >
                                {m.icon}
                                <span>{m.label}</span>
                            </NavLink>
                        ))}
                    </div>
                </div>

                <div className="sidebar-divider"></div>

                <SidebarItem 
                    to="/ai" 
                    icon={<Sparkles size={20} />} 
                    label="AI Assistant" 
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                />
                <SidebarItem 
                    to="/reports" 
                    icon={<Download size={20} />} 
                    label="Export Reports" 
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                />
            </nav>

            {/* Footer */}
            <div className="flex-col items-center gap-4 pt-4 w-full flex">
                <ThemeToggle />
                <button 
                    onClick={handleLogout}
                    className="nav-item btn-ghost" 
                    title="Logout" 
                    style={{
                        background: 'transparent', 
                        width: 'auto', 
                        height: 'auto', 
                        padding: '0.5rem', 
                        marginBottom: '1rem',
                        cursor: 'pointer'
                    }}
                >
                    <LogOut size={20} />
                </button>
            </div>


            {/* Hoisted Tooltip */}
            {tooltip && (
                <div 
                    className="tooltip"
                    style={{
                        position: 'fixed',
                        left: '80px',
                        top: tooltip.top,
                        marginLeft: '0.5rem',
                        opacity: 1,
                        transform: 'translateY(-50%)',
                        zIndex: 100
                    }}
                >
                    {tooltip.label}
                </div>
            )}
        </aside>
    );
};
