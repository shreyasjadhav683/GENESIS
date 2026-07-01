import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { 
    LayoutDashboard, 
    History, 
    Menu, 
    X,
    User,
    // Feature Icons matching Dashboard
    Search, 
    Link, 
    FileCheck, 
    FileCode, 
    Shield, 
    Fish, 
    Mail, 
    ShieldAlert, 
    Bug, 
    Cpu, 
    Download,
    Puzzle
} from 'lucide-react';



export const MobileNavbar: React.FC = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const [showMenu, setShowMenu] = useState(false);

    const navItems = [
        { id: 'dashboard', label: 'Home', icon: <LayoutDashboard size={20} />, path: '/' },
        { id: 'history', label: 'History', icon: <History size={20} />, path: '/history' },
        { id: 'profile', label: 'Profile', icon: <User size={20} />, path: '/profile' },
    ];

    // Icons matched exactly from Dashboard.tsx
    const menuItems = [
        { label: 'IP Scanner', icon: <Search size={18} />, path: '/ip' },
        { label: 'URL Scanner', icon: <Link size={18} />, path: '/url' },
        { label: 'File Integrity', icon: <FileCheck size={18} />, path: '/files/integrity' },
        { label: 'Metadata Viewer', icon: <FileCode size={18} />, path: '/files/metadata' },
        { label: 'Security Headers', icon: <Shield size={18} />, path: '/scan/security-headers' },
        { label: 'Phishing Detector', icon: <Fish size={18} />, path: '/scan/phishing' },
        { label: 'Email Headers', icon: <Mail size={18} />, path: '/scan/email-headers' },
        { label: 'Password Strength', icon: <ShieldAlert size={18} />, path: '/scan/password' },
        { label: 'Code Scanner', icon: <Bug size={18} />, path: '/scan/code' },
        { label: 'Ransomware Detect', icon: <ShieldAlert size={18} />, path: '/scan/ransomware' },
        { label: 'Extension Scanner', icon: <Puzzle size={18} />, path: '/scan/extensions' },
        { label: 'AI Assistant', icon: <Cpu size={18} />, path: '/ai' },
        { label: 'Export Reports', icon: <Download size={18} />, path: '/reports' },
    ];

    return (
        <>
            {/* Bottom Navigation Bar */}
            <div className="mobile-navbar">
                {navItems.map((item) => (
                    <button
                        key={item.id}
                        className={`mobile-nav-item ${location.pathname === item.path ? 'active' : ''}`}
                        onClick={() => navigate(item.path)}
                    >
                        {item.icon}
                        <span>{item.label}</span>
                    </button>
                ))}
                
                {/* Menu Button for Features */}
                <button
                    className={`mobile-nav-item ${showMenu ? 'active' : ''}`}
                    onClick={() => setShowMenu(!showMenu)}
                >
                    <Menu size={20} />
                    <span>Features</span>
                </button>
            </div>

            {/* Mobile Feature Menu Overlay */}
            {showMenu && (
                <div className="mobile-menu-overlay">
                    <div className="mobile-menu-content">
                        <div className="mobile-menu-header">
                            <h3>Security Modules</h3>
                            <button className="close-btn" onClick={() => setShowMenu(false)}>
                                <X size={24} />
                            </button>
                        </div>
                        <div className="mobile-menu-grid">
                            {menuItems.map((item, index) => (
                                <button
                                    key={index}
                                    className="mobile-menu-item"
                                    onClick={() => {
                                        navigate(item.path);
                                        setShowMenu(false);
                                    }}
                                >
                                    <div className="mobile-menu-icon">{item.icon}</div>
                                    <span>{item.label}</span>
                                </button>
                            ))}
                        </div>
                    </div>
                </div>
            )}
        </>
    );
};
