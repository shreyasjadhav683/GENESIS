import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Card } from '../components/Card';
import { api } from '../services/api';
import { 
    User, 
    Mail, 
    Shield, 
    LogOut,
    ChevronRight,
    CheckCircle,
    BookOpen,
    Scale,
    AlertTriangle,
    Cpu,
    Info,
    Edit2,
    Save,
    X,
    Lock
} from 'lucide-react';

export const Profile = () => {
    const { user, logout, refreshUser } = useAuth();
    const navigate = useNavigate();
    const [activeSection, setActiveSection] = useState<string | null>(null);
    const [isEditing, setIsEditing] = useState(false);
    
    // Form State
    const [formData, setFormData] = useState({
        username: user?.username || '',
        email: user?.email || '',
        security_question: '',
        security_answer: ''
    });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<string | null>(null);

    // Initialize form when user data is available
    useEffect(() => {
        if (user) {
            setFormData(prev => ({
                ...prev,
                username: user.username,
                email: user.email
            }));
            fetchSecurityQuestion();
        }
    }, [user]);

    const fetchSecurityQuestion = async () => {
        try {
            if (user?.username) {
                const response = await api.post('/auth/security-question', { username: user.username });
                setFormData(prev => ({ ...prev, security_question: response.data.security_question }));
            }
        } catch (err) {
            console.error("Failed to fetch security question", err);
        }
    };

    const menuItems = [
        {
            id: 'security',
            icon: <Shield size={20} />,
            label: 'Security Settings',
            description: 'Change password',
            color: 'hsl(var(--color-primary))'
        },
        {
            id: 'manual',
            icon: <BookOpen size={20} />,
            label: 'User Manual',
            description: 'How to use Genesis',
            color: 'hsl(var(--color-secondary))'
        },
        {
            id: 'privacy',
            icon: <Scale size={20} />,
            label: 'Privacy Policy',
            description: 'Data handling & privacy',
            color: 'hsl(var(--color-info))'
        },
        {
            id: 'about',
            icon: <Info size={20} />,
            label: 'About Genesis',
            description: 'Version & credits',
            color: 'hsl(var(--color-warning))'
        },
    ];

    const handleMenuClick = (id: string) => {
        if (id === 'security') {
            navigate('/change-password');
        } else {
            setActiveSection(activeSection === id ? null : id);
        }
    };

    const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
        setFormData(prev => ({ ...prev, [name]: value }));
    };

    const handleSaveProfile = async () => {
        setLoading(true);
        setError(null);
        setSuccess(null);

        try {
            const updatePayload: any = {};
            if (formData.username !== user?.username) updatePayload.username = formData.username;
            if (formData.email !== user?.email) updatePayload.email = formData.email;
            if (formData.security_question && formData.security_answer) {
                 updatePayload.security_question = formData.security_question;
                 updatePayload.security_answer = formData.security_answer;
            } else if ((formData.security_question && !formData.security_answer) || (!formData.security_question && formData.security_answer)) {
                 if (formData.security_question !== user?.security_question) {
                     setError("Please provide an answer if you are setting a Security Question");
                     setLoading(false);
                     return;
                 }
            }
            
            if (Object.keys(updatePayload).length === 0) {
                setIsEditing(false);
                setLoading(false);
                return;
            }

            await api.put('/users/me', updatePayload);
            
            setSuccess("Profile updated successfully");
            setIsEditing(false);
            
            // Refresh user data in context to reflect changes everywhere
            await refreshUser();

        } catch (err: any) {
            setError(err.response?.data?.detail || "Failed to update profile");
        } finally {
            setLoading(false);
        }
    };

    const handleCancelEdit = () => {
        setIsEditing(false);
        setFormData(prev => ({
            ...prev,
            username: user?.username || '',
            email: user?.email || '',
            security_answer: ''
        }));
        setError(null);
    };

    return (
        <div style={{ maxWidth: '800px', margin: '0 auto' }}>
            {/* Page Header */}
            <div className="page-header" style={{ marginBottom: '2rem' }}>
                <div className="page-header-icon">
                    <User size={28} />
                </div>
                <div className="page-header-content">
                    <h1>Profile & Settings</h1>
                    <p>Manage your account and preferences</p>
                </div>
            </div>

            {/* Error/Success Messages */}
            {error && (
                <div style={{ padding: '0.75rem', background: 'hsla(var(--color-error), 0.1)', color: 'hsl(var(--color-error))', marginBottom: '1rem', borderRadius: 'var(--radius-md)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <AlertTriangle size={16} /> {error}
                </div>
            )}
            {success && (
                <div style={{ padding: '0.75rem', background: 'hsla(var(--color-success), 0.1)', color: 'hsl(var(--color-success))', marginBottom: '1rem', borderRadius: 'var(--radius-md)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <CheckCircle size={16} /> {success}
                </div>
            )}

            {/* User Info Card */}
            <Card style={{ marginBottom: '1.5rem', position: 'relative' }}>
                {!isEditing && (
                    <button 
                        onClick={() => setIsEditing(true)}
                        style={{
                            position: 'absolute',
                            top: '1rem',
                            right: '1rem',
                            background: 'transparent',
                            border: '1px solid hsl(var(--border-color))',
                            padding: '0.5rem',
                            borderRadius: 'var(--radius-md)',
                            cursor: 'pointer',
                            color: 'hsl(var(--text-secondary))',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.5rem',
                            fontSize: '0.875rem'
                        }}
                    >
                        <Edit2 size={16} /> Edit Profile
                    </button>
                )}

                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1.5rem', flexWrap: 'wrap' }}>
                    {/* Avatar */}
                    <div style={{
                        width: '80px',
                        height: '80px',
                        borderRadius: 'var(--radius-full)',
                        background: 'var(--gradient-primary)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: '2rem',
                        fontWeight: 'bold',
                        color: '#0a0a12',
                        flexShrink: 0
                    }}>
                        {user?.username?.charAt(0).toUpperCase() || 'U'}
                    </div>
                    
                    {/* User Details Form/View */}
                    <div style={{ flex: 1, minWidth: '200px' }}>
                        {isEditing ? (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                                <div>
                                    <label style={{ display: 'block', fontSize: '0.75rem', color: 'hsl(var(--text-muted))', marginBottom: '0.25rem' }}>Username</label>
                                    <input 
                                        type="text" 
                                        name="username"
                                        value={formData.username}
                                        onChange={handleInputChange}
                                        className="input-field" // Assuming global class or reuse style
                                        style={{ width: '100%', padding: '0.5rem', background: 'hsl(var(--bg-secondary))', border: '1px solid hsl(var(--border-color))', borderRadius: 'var(--radius-sm)', color: 'hsl(var(--text-primary))' }}
                                    />
                                </div>
                                <div>
                                    <label style={{ display: 'block', fontSize: '0.75rem', color: 'hsl(var(--text-muted))', marginBottom: '0.25rem' }}>Email</label>
                                    <input 
                                        type="email" 
                                        name="email"
                                        value={formData.email}
                                        onChange={handleInputChange}
                                        style={{ width: '100%', padding: '0.5rem', background: 'hsl(var(--bg-secondary))', border: '1px solid hsl(var(--border-color))', borderRadius: 'var(--radius-sm)', color: 'hsl(var(--text-primary))' }}
                                    />
                                </div>
                                
                                <div style={{ borderTop: '1px solid hsl(var(--border-color))', paddingTop: '1rem', marginTop: '0.5rem' }}>
                                    <p style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                        <Lock size={14} /> Update Security Question
                                    </p>
                                    <div style={{ marginBottom: '0.75rem' }}>
                                        <label style={{ display: 'block', fontSize: '0.75rem', color: 'hsl(var(--text-muted))', marginBottom: '0.25rem' }}>Security Question</label>
                                        <input 
                                            type="text" 
                                            name="security_question"
                                            value={formData.security_question}
                                            onChange={handleInputChange}
                                            placeholder="e.g., What is your pet's name?"
                                            style={{ width: '100%', padding: '0.5rem', background: 'hsl(var(--bg-secondary))', border: '1px solid hsl(var(--border-color))', borderRadius: 'var(--radius-sm)', color: 'hsl(var(--text-primary))' }}
                                        />
                                    </div>
                                    <div>
                                        <label style={{ display: 'block', fontSize: '0.75rem', color: 'hsl(var(--text-muted))', marginBottom: '0.25rem' }}>Security Answer</label>
                                        <input 
                                            type="text" 
                                            name="security_answer"
                                            value={formData.security_answer}
                                            onChange={handleInputChange}
                                            placeholder="Update your answer if changing question"
                                            style={{ width: '100%', padding: '0.5rem', background: 'hsl(var(--bg-secondary))', border: '1px solid hsl(var(--border-color))', borderRadius: 'var(--radius-sm)', color: 'hsl(var(--text-primary))' }}
                                        />
                                    </div>
                                </div>

                                <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
                                    <button 
                                        onClick={handleSaveProfile}
                                        disabled={loading}
                                        style={{ 
                                            background: 'var(--gradient-primary)', 
                                            color: '#000', 
                                            border: 'none', 
                                            padding: '0.5rem 1rem', 
                                            borderRadius: 'var(--radius-md)', 
                                            fontWeight: 600, 
                                            display: 'flex', 
                                            alignItems: 'center', 
                                            gap: '0.5rem',
                                            cursor: loading ? 'not-allowed' : 'pointer',
                                            opacity: loading ? 0.7 : 1
                                        }}
                                    >
                                        <Save size={16} /> {loading ? 'Saving...' : 'Save Changes'}
                                    </button>
                                    <button 
                                        onClick={handleCancelEdit}
                                        disabled={loading}
                                        style={{ 
                                            background: 'transparent', 
                                            color: 'hsl(var(--text-secondary))', 
                                            border: '1px solid hsl(var(--border-color))', 
                                            padding: '0.5rem 1rem', 
                                            borderRadius: 'var(--radius-md)', 
                                            display: 'flex', 
                                            alignItems: 'center', 
                                            gap: '0.5rem',
                                            cursor: 'pointer'
                                        }}
                                    >
                                        <X size={16} /> Cancel
                                    </button>
                                </div>
                            </div>
                        ) : (
                            <>
                                <h2 style={{ 
                                    fontSize: '1.5rem', 
                                    fontWeight: 700, 
                                    marginBottom: '0.25rem',
                                    color: 'hsl(var(--text-primary))'
                                }}>
                                    {user?.username || 'User'}
                                </h2>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'hsl(var(--text-secondary))' }}>
                                    <Mail size={16} />
                                    <span style={{ fontSize: '0.875rem' }}>{user?.email || 'No email'}</span>
                                </div>
                                <div style={{ 
                                    display: 'flex', 
                                    alignItems: 'center', 
                                    gap: '0.5rem', 
                                    marginTop: '0.5rem',
                                    color: user?.is_active ? 'hsl(var(--color-success))' : 'hsl(var(--color-error))'
                                }}>
                                    <CheckCircle size={14} />
                                    <span style={{ fontSize: '0.75rem', fontWeight: 600 }}>
                                        {user?.is_active ? 'Account Active' : 'Account Inactive'}
                                    </span>
                                </div>
                            </>
                        )}
                    </div>
                </div>
            </Card>

            {/* Menu Items */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {menuItems.map((item) => (
                    <div key={item.id}>
                        <button
                            onClick={() => handleMenuClick(item.id)}
                            style={{
                                width: '100%',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '1rem',
                                padding: '1rem 1.25rem',
                                background: 'hsl(var(--bg-card))',
                                border: `1px solid ${activeSection === item.id ? item.color : 'hsl(var(--border-color))'}`,
                                borderRadius: 'var(--radius-lg)',
                                cursor: 'pointer',
                                transition: 'all 0.2s ease',
                                textAlign: 'left'
                            }}
                        >
                            <div style={{
                                width: '40px',
                                height: '40px',
                                borderRadius: 'var(--radius-md)',
                                background: `${item.color}20`,
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                color: item.color,
                                flexShrink: 0
                            }}>
                                {item.icon}
                            </div>
                            <div style={{ flex: 1 }}>
                                <p style={{ 
                                    fontWeight: 600, 
                                    color: 'hsl(var(--text-primary))',
                                    marginBottom: '0.125rem'
                                }}>
                                    {item.label}
                                </p>
                                <p style={{ 
                                    fontSize: '0.75rem', 
                                    color: 'hsl(var(--text-muted))' 
                                }}>
                                    {item.description}
                                </p>
                            </div>
                            <ChevronRight 
                                size={20} 
                                style={{ 
                                    color: 'hsl(var(--text-muted))',
                                    transform: activeSection === item.id ? 'rotate(90deg)' : 'none',
                                    transition: 'transform 0.2s'
                                }} 
                            />
                        </button>
                        
                        {/* Expandable Content */}
                        {activeSection === item.id && (
                            <div style={{
                                padding: '1.25rem',
                                marginTop: '0.5rem',
                                background: 'hsl(var(--bg-secondary))',
                                borderRadius: 'var(--radius-lg)',
                                border: '1px solid hsl(var(--border-color))',
                                animation: 'fadeIn 0.3s ease'
                            }}>
                                {item.id === 'manual' && <UserManualContent />}
                                {item.id === 'privacy' && <PrivacyPolicyContent />}
                                {item.id === 'about' && <AboutContent />}
                            </div>
                        )}
                    </div>
                ))}

                {/* Logout Button */}
                <button
                    onClick={logout}
                    style={{
                        width: '100%',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '1rem',
                        padding: '1rem 1.25rem',
                        background: 'hsl(var(--color-error-light))',
                        border: '1px solid hsla(var(--color-error), 0.3)',
                        borderRadius: 'var(--radius-lg)',
                        cursor: 'pointer',
                        transition: 'all 0.2s ease',
                        textAlign: 'left',
                        marginTop: '1rem'
                    }}
                >
                    <div style={{
                        width: '40px',
                        height: '40px',
                        borderRadius: 'var(--radius-md)',
                        background: 'hsla(var(--color-error), 0.2)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: 'hsl(var(--color-error))',
                        flexShrink: 0
                    }}>
                        <LogOut size={20} />
                    </div>
                    <div style={{ flex: 1 }}>
                        <p style={{ 
                            fontWeight: 600, 
                            color: 'hsl(var(--color-error))'
                        }}>
                            Logout
                        </p>
                        <p style={{ 
                            fontSize: '0.75rem', 
                            color: 'hsla(var(--color-error), 0.8)' 
                        }}>
                            Sign out of your account
                        </p>
                    </div>
                </button>
            </div>
        </div>
    );
};

// --- Expandable Content Components ---
// (Keeping existing components below as they were likely part of the original file not shown in the snippet above, or I should re-add them if they were in the truncation zone)

const UserManualContent = () => (
    <div style={{ lineHeight: 1.8 }}>
        <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <BookOpen size={18} /> Getting Started with Genesis
        </h3>
        
        <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ color: 'hsl(var(--color-primary))', marginBottom: '0.5rem' }}>🔍 Scanners</h4>
            <ul style={{ paddingLeft: '1.25rem', color: 'hsl(var(--text-secondary))' }}>
                <li><strong>IP Scanner:</strong> Analyze IP addresses for threat intelligence, geolocation, and abuse history.</li>
                <li><strong>URL Scanner:</strong> Check URLs for malware, phishing, and suspicious behavior.</li>
                <li><strong>File Integrity:</strong> Compute SHA256/MD5 hashes and compare against baselines.</li>
                <li><strong>Metadata Viewer:</strong> Extract hidden EXIF data from images and documents.</li>
            </ul>
        </div>

        <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ color: 'hsl(var(--color-secondary))', marginBottom: '0.5rem' }}>🛡️ Security Tools</h4>
            <ul style={{ paddingLeft: '1.25rem', color: 'hsl(var(--text-secondary))' }}>
                <li><strong>Security Headers:</strong> Validate HTTP security headers of websites.</li>
                <li><strong>Phishing Detector:</strong> Identify phishing and scam URLs.</li>
                <li><strong>Email Headers:</strong> Analyze email authentication (SPF, DKIM, DMARC).</li>
                <li><strong>Password Strength:</strong> Test password entropy and estimated crack time.</li>
                <li><strong>Code Scanner:</strong> Static code analysis for security vulnerabilities.</li>
                <li><strong>Ransomware Detect:</strong> Heuristic analysis for ransomware patterns.</li>
            </ul>
        </div>

        <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ color: 'hsl(var(--color-info))', marginBottom: '0.5rem' }}>💡 Tips</h4>
            <ul style={{ paddingLeft: '1.25rem', color: 'hsl(var(--text-secondary))' }}>
                <li>All scan results are automatically saved to <strong>History</strong>.</li>
                <li>Export comprehensive reports from the <strong>Reports</strong> page.</li>
                <li>Use the <strong>AI Assistant</strong> for security policy advice.</li>
            </ul>
        </div>
    </div>
);

const PrivacyPolicyContent = () => (
    <div style={{ lineHeight: 1.8 }}>
        <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Scale size={18} /> Privacy Policy
        </h3>
        
        <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ color: 'hsl(var(--color-primary))', marginBottom: '0.5rem' }}>Data Collection</h4>
            <p style={{ color: 'hsl(var(--text-secondary))' }}>
                Genesis collects only the information necessary to provide its services:
            </p>
            <ul style={{ paddingLeft: '1.25rem', color: 'hsl(var(--text-secondary))', marginTop: '0.5rem' }}>
                <li>Account information (username, email)</li>
                <li>Scan history and results</li>
                <li>Files uploaded for analysis (processed locally, not stored permanently)</li>
            </ul>
        </div>

        <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ color: 'hsl(var(--color-secondary))', marginBottom: '0.5rem' }}>Data Usage</h4>
            <p style={{ color: 'hsl(var(--text-secondary))' }}>
                Your data is used exclusively for:
            </p>
            <ul style={{ paddingLeft: '1.25rem', color: 'hsl(var(--text-secondary))', marginTop: '0.5rem' }}>
                <li>Providing security analysis services</li>
                <li>Maintaining scan history for your reference</li>
                <li>Improving the accuracy of threat detection</li>
            </ul>
        </div>

        <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ color: 'hsl(var(--color-warning))', marginBottom: '0.5rem' }}>
                <AlertTriangle size={16} style={{ display: 'inline', marginRight: '0.25rem' }} />
                Important
            </h4>
            <p style={{ color: 'hsl(var(--text-secondary))' }}>
                Genesis is designed for cybersecurity professionals and educational purposes. 
                Do not use this tool for malicious activities. 
                We do not share your data with third parties.
            </p>
        </div>
    </div>
);

const AboutContent = () => (
    <div style={{ lineHeight: 1.8 }}>
        <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Cpu size={18} /> About Genesis
        </h3>
        
        <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: '1rem', 
            marginBottom: '1.5rem',
            padding: '1rem',
            background: 'hsl(var(--bg-card))',
            borderRadius: 'var(--radius-md)',
            border: '1px solid hsl(var(--border-color))'
        }}>
            <div style={{
                width: '60px',
                height: '60px',
                borderRadius: 'var(--radius-lg)',
                background: 'var(--gradient-accent)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
            }}>
                <Shield size={32} style={{ color: '#0a0a12' }} />
            </div>
            <div>
                <h4 style={{ color: 'hsl(var(--text-primary))' }}>GENESIS</h4>
                <p style={{ fontSize: '0.875rem', color: 'hsl(var(--text-muted))' }}>
                    Cybersecurity Analysis Platform
                </p>
                <p style={{ 
                    fontSize: '0.75rem', 
                    color: 'hsl(var(--color-primary))',
                    fontFamily: 'monospace'
                }}>
                    Version 1.0.0
                </p>
            </div>
        </div>

        <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ color: 'hsl(var(--color-secondary))', marginBottom: '0.5rem' }}>Features</h4>
            <div style={{ 
                display: 'grid', 
                gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
                gap: '0.5rem'
            }}>
                {['IP Analysis', 'URL Scanning', 'File Integrity', 'Metadata Extraction', 
                  'Email Analysis', 'Phishing Detection', 'Password Testing', 'Code Scanning',
                  'AI Assistant', 'Report Export'].map((feature) => (
                    <div key={feature} style={{
                        padding: '0.5rem',
                        background: 'hsl(var(--bg-card))',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '0.75rem',
                        color: 'hsl(var(--text-secondary))',
                        textAlign: 'center'
                    }}>
                        {feature}
                    </div>
                ))}
            </div>
        </div>

        <div style={{ color: 'hsl(var(--text-muted))', fontSize: '0.75rem', textAlign: 'center' }}>
            <p>Built with React, FastAPI, and SQLModel</p>
            <p style={{ marginTop: '0.25rem' }}>© 2026 Genesis Security Platform</p>
        </div>
    </div>
);
