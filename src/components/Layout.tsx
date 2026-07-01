import React from 'react';
import { Sidebar } from './Sidebar';
import { MobileNavbar } from './MobileNavbar';
import { Outlet, Link } from 'react-router-dom';
import { User } from 'lucide-react';

export const Layout: React.FC = () => {
  return (
    <div className="app-container">
      {/* Sidebar - Hidden on Mobile */}
      <div className="desktop-sidebar">
        <Sidebar />
      </div>

      {/* Main Content Area */}
      <div className="main-content">
        
        {/* Top Bar */}
        <header className="top-bar">
            <h1 style={{ fontSize: '1.25rem', fontWeight: 'bold', letterSpacing: '0.1em', opacity: 0.8 }}>
                GENESIS <span style={{ color: 'hsl(var(--color-primary))' }}>///</span> DASHBOARD
            </h1>
            <div className="connection-status" style={{ display: 'flex', alignItems: 'center', gap: '1rem', fontSize: '0.75rem', fontFamily: 'monospace', color: 'hsl(var(--text-secondary))' }}>
                <span className="hidden-mobile">SECURE_CONNECTION: ENCRYPTED</span>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#4ade80' }} className="animate-pulse"></span>
                <div style={{ width: '1px', height: '24px', background: 'hsl(var(--border-color))', margin: '0 0.5rem' }}></div>
                <Link to="/profile" className="profile-link" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'hsl(var(--text-primary))', textDecoration: 'none', padding: '0.25rem 0.5rem', borderRadius: 'var(--radius-md)', transition: 'background 0.2s', fontSize: '0.875rem' }}>
                    <div style={{ background: 'hsla(var(--color-primary), 0.1)', padding: '0.25rem', borderRadius: '50%' }}>
                        <User size={16} color="hsl(var(--color-primary))" />
                    </div>
                    <span className="hidden-mobile" style={{ fontWeight: 600 }}>Profile</span>
                </Link>
            </div>
        </header>

        {/* Content */}
        <main className="page-content">
            <Outlet />
        </main>
        
        {/* Mobile Navbar - Visible only on Mobile */}
        <div className="mobile-navbar-container">
            <MobileNavbar />
        </div>
      </div>
    </div>
  );
};
