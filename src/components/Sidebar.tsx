
import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { ThemeToggle } from './ThemeToggle';
import { 
    Key, Home, Search, Link, FileCheck, FileCode, 
    ShieldAlert, Bug, Download, LogOut,
    Mail, Shield, Fish, Puzzle, Sparkles, Globe, Lock
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
                
                <SidebarItem 
                    to="/ip" 
                    icon={<Search size={20} />} 
                    label="IP Scanner" 
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                />
                <SidebarItem 
                    to="/url" 
                    icon={<Link size={20} />} 
                    label="URL Scanner" 
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                />
                <SidebarItem 
                    to="/files/integrity" 
                    icon={<FileCheck size={20} />} 
                    label="File Integrity" 
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                />
                <SidebarItem 
                    to="/files/metadata" 
                    icon={<FileCode size={20} />} 
                    label="Metadata" 
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                />
                <SidebarItem 
                    to="/scan/email-headers" 
                    icon={<Mail size={20} />} 
                    label="Email Analyzer" 
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                />
                <SidebarItem 
                    to="/scan/security-headers" 
                    icon={<Shield size={20} />} 
                    label="Security Headers" 
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                />
                <SidebarItem 
                    to="/scan/phishing" 
                    icon={<Fish size={20} />} 
                    label="Phishing Detector" 
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                />
                <SidebarItem 
                    to="/scan/password" 
                    icon={({ isActive }) => <Key size={20} color={isActive ? "currentColor" : undefined} />} 
                    label="Password Strength" 
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                />
                <SidebarItem 
                    to="/scan/code" 
                    icon={<Bug size={20} />} 
                    label="Code Scanner" 
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                />
                <SidebarItem 
                    to="/scan/ransomware" 
                    icon={({ isActive }) => <ShieldAlert size={20} color={isActive ? "currentColor" : undefined} />} 
                    label="Ransomware" 
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                />
                <SidebarItem 
                    to="/scan/extensions" 
                    icon={({ isActive }) => <Puzzle size={20} color={isActive ? "currentColor" : undefined} />} 
                    label="Extension Scanner" 
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                />
                <SidebarItem 
                    to="/whois-dns" 
                    icon={<Globe size={20} />} 
                    label="WHOIS & DNS" 
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                />
                <SidebarItem 
                    to="/scan/ssl" 
                    icon={<Lock size={20} />} 
                    label="SSL Checker" 
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                />
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
