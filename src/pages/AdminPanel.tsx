import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

const formatDate = (dateStr: string | null | undefined) => {
  if (!dateStr) return 'N/A';
  const d = dateStr.endsWith('Z') ? dateStr : dateStr + 'Z';
  return new Date(d).toLocaleString();
};

interface UserRecord {
  id: number;
  username: string;
  email: string;
  is_active: boolean;
  is_superuser: boolean;
  security_question: string;
  last_active?: string;
}

interface Stats {
  total_users: number;
  active_users: number;
  inactive_users: number;
  admin_users: number;
}

const getActivityStatus = (u: UserRecord): 'Online' | 'Offline' | 'Disabled' => {
  if (!u.is_active) return 'Disabled';
  if (u.last_active) {
    const lastStr = u.last_active.endsWith('Z') ? u.last_active : u.last_active + 'Z';
    const lastTime = new Date(lastStr).getTime();
    if (new Date().getTime() - lastTime < 15 * 60 * 1000) return 'Online';
  }
  return 'Offline';
};

interface AdminInfo {
  id: number;
  username: string;
  email: string;
}

// Axios instance that always sends the admin token
const adminApi = axios.create({ baseURL: API_URL });
adminApi.interceptors.request.use((config: any) => {
  const token = localStorage.getItem('admin_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export default function AdminPanel() {
  const navigate = useNavigate();
  const [adminInfo, setAdminInfo] = useState<AdminInfo | null>(() => {
    try { return JSON.parse(localStorage.getItem('admin_info') || 'null'); }
    catch { return null; }
  });

  const [users, setUsers]         = useState<UserRecord[]>([]);
  const [stats, setStats]         = useState<Stats | null>(null);
  const [insights, setInsights]   = useState<any | null>(null);
  const [loading, setLoading]     = useState(true);
  const [actioning, setActioning] = useState<number | null>(null);
  const [error, setError]         = useState('');
  const [search, setSearch]       = useState('');
  const [filter, setFilter]       = useState<'all' | 'active' | 'inactive' | 'admin'>('all');
  const [toast, setToast]         = useState<{ msg: string; ok: boolean } | null>(null);
  const [delTarget, setDelTarget] = useState<UserRecord | null>(null);
  const [activeTab, setActiveTab] = useState<'clients' | 'admins' | 'insights' | 'settings'>('clients');
  const [viewUser, setViewUser]   = useState<UserRecord | null>(null);
  const [userDetails, setUserDetails] = useState<any | null>(null);

  /* ── Guard: must have admin token ── */
  useEffect(() => {
    if (!localStorage.getItem('admin_token')) navigate('/admin-login', { replace: true });
  }, [navigate]);

  const toast$ = (msg: string, ok = true) => {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 3500);
  };

  /* ── Fetch data ── */
  const fetchAll = useCallback(async () => {
    try {
      const [u, s, ins] = await Promise.all([
        adminApi.get('/admin/users'),
        adminApi.get('/admin/stats'),
        adminApi.get('/admin/insights'),
      ]);
      setUsers(u.data);
      setStats(s.data);
      setInsights(ins.data);
    } catch (e: any) {
      if (e.response?.status === 401 || e.response?.status === 403) {
        localStorage.removeItem('admin_token');
        navigate('/admin-login', { replace: true });
      } else {
        setError('Failed to load data. ' + (e.response?.data?.detail || ''));
      }
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  /* ── Actions ── */
  const toggleActive = async (u: UserRecord) => {
    setActioning(u.id);
    try {
      await adminApi.patch(`/admin/users/${u.id}/toggle-active`);
      setUsers(prev => prev.map(x => x.id === u.id ? { ...x, is_active: !x.is_active } : x));
      setStats(prev => prev ? {
        ...prev,
        active_users: u.is_active ? prev.active_users - 1 : prev.active_users + 1,
        inactive_users: u.is_active ? prev.inactive_users + 1 : prev.inactive_users - 1,
      } : prev);
      toast$(`${u.username} ${u.is_active ? 'disabled' : 'enabled'}`);
    } catch (e: any) { toast$(e.response?.data?.detail || 'Failed', false); }
    finally { setActioning(null); }
  };

  const toggleSuperuser = async (u: UserRecord) => {
    setActioning(u.id);
    try {
      await adminApi.patch(`/admin/users/${u.id}/toggle-superuser`);
      setUsers(prev => prev.map(x => x.id === u.id ? { ...x, is_superuser: !x.is_superuser } : x));
      toast$(`${u.username} ${u.is_superuser ? 'demoted to user' : 'promoted to admin'}`);
    } catch (e: any) { toast$(e.response?.data?.detail || 'Failed', false); }
    finally { setActioning(null); }
  };

  const deleteUser = async (u: UserRecord) => {
    setActioning(u.id);
    setDelTarget(null);
    try {
      await adminApi.delete(`/admin/users/${u.id}`);
      setUsers(prev => prev.filter(x => x.id !== u.id));
      setStats(prev => prev ? {
        ...prev,
        total_users: prev.total_users - 1,
        active_users: u.is_active ? prev.active_users - 1 : prev.active_users,
        inactive_users: !u.is_active ? prev.inactive_users - 1 : prev.inactive_users,
        admin_users: u.is_superuser ? prev.admin_users - 1 : prev.admin_users,
      } : prev);
      toast$(`"${u.username}" deleted`);
    } catch (e: any) { toast$(e.response?.data?.detail || 'Delete failed', false); }
    finally { setActioning(null); }
  };

  const fetchUserDetails = async (u: UserRecord) => {
    setViewUser(u);
    setUserDetails(null);
    try {
      const res = await adminApi.get(`/admin/users/${u.id}/details`);
      setUserDetails(res.data);
    } catch (e: any) {
      toast$(e.response?.data?.detail || 'Failed to fetch user details', false);
      setViewUser(null);
    }
  };

  const logout = () => {
    localStorage.removeItem('admin_token');
    localStorage.removeItem('admin_info');
    navigate('/admin-login', { replace: true });
  };

  /* ── Filtered view ── */
  const filtered = users.filter(u => {
    const q = search.toLowerCase();
    const matchSearch = !q || u.username.toLowerCase().includes(q) || u.email.toLowerCase().includes(q);
    
    const status = getActivityStatus(u);
    const matchFilter =
      filter === 'all'      ? true :
      filter === 'active'   ? status === 'Online' :
      filter === 'inactive' ? status !== 'Online' :
      u.is_superuser;
      
    const matchTab = activeTab === 'admins' ? u.is_superuser : !u.is_superuser;
    return matchSearch && matchFilter && matchTab;
  });

  /* ── States ── */
  if (loading) return (
    <div style={s.center}>
      <div style={s.spinner} />
      <p style={{ color: '#475569', marginTop: 16, fontSize: 14 }}>Loading admin panel…</p>
    </div>
  );

  if (error) return (
    <div style={s.center}>
      <span style={{ fontSize: 48 }}>🚫</span>
      <p style={{ color: '#f87171', marginTop: 12 }}>{error}</p>
      <button style={s.outlineBtn} onClick={fetchAll}>Retry</button>
    </div>
  );

  return (
    <div style={s.page} className="admin-page">
      <style>{`
        @media (max-width: 768px) {
          .admin-page { flex-direction: column !important; }
          .admin-sidebar { width: 100% !important; height: auto !important; position: static !important; padding: 16px !important; border-right: none !important; border-bottom: 1px solid #0f172a !important; }
          .admin-nav { flex-direction: row !important; overflow-x: auto !important; padding-bottom: 8px !important; }
          .admin-nav::-webkit-scrollbar { display: none; }
          .admin-nav-item { white-space: nowrap !important; }
          .admin-main { padding: 16px !important; }
          .admin-header { flex-direction: column !important; align-items: flex-start !important; }
          .admin-header-actions { width: 100% !important; justify-content: space-between !important; margin-top: 16px !important; }
          .admin-stats { grid-template-columns: 1fr 1fr !important; }
          .admin-controls { flex-direction: column !important; align-items: stretch !important; }
          .admin-search { width: 100% !important; }
          .admin-filters { overflow-x: auto !important; width: 100% !important; justify-content: space-between !important; }
          .admin-insights-grid { grid-template-columns: 1fr !important; }
          .user-details-grid { grid-template-columns: 1fr !important; }
        }
        @media (max-width: 480px) {
          .admin-stats { grid-template-columns: 1fr !important; }
        }
      `}</style>
      {/* Grid BG */}
      <div style={s.gridBg} />

      {/* Toast */}
      {toast && (
        <div style={{ ...s.toast, background: toast.ok ? '#16a34a' : '#dc2626' }}>
          {toast.ok ? '✓' : '✗'} {toast.msg}
        </div>
      )}

      {/* Delete Confirm Modal */}
      {delTarget && (
        <div style={s.overlay}>
          <div style={s.modal}>
            <div style={{ fontSize: 40, textAlign: 'center', marginBottom: 12 }}>⚠️</div>
            <h3 style={{ color: '#f87171', textAlign: 'center', margin: '0 0 8px' }}>Delete User?</h3>
            <p style={{ color: '#94a3b8', textAlign: 'center', margin: '0 0 24px', fontSize: 14 }}>
              <strong style={{ color: '#e2e8f0' }}>{delTarget.username}</strong> ({delTarget.email}) will be permanently removed.
            </p>
            <div style={{ display: 'flex', gap: 10 }}>
              <button style={s.outlineBtn} onClick={() => setDelTarget(null)}>Cancel</button>
              <button style={s.redBtn} onClick={() => deleteUser(delTarget)}>Delete</button>
            </div>
          </div>
        </div>
      )}

      {/* ── Sidebar ── */}
      <aside style={s.sidebar} className="admin-sidebar">
        <div style={s.brand}>
          <div style={s.brandIcon}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#dc2626" strokeWidth="2.5" strokeLinecap="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <div>
            <div style={s.brandName}>Genesis</div>
            <div style={s.brandSub}>Admin Panel</div>
          </div>
        </div>

        <nav style={s.nav} className="admin-nav">
          {[
            { id: 'clients',  label: 'Clients',  icon: '👥', count: users.filter(u => !u.is_superuser).length },
            { id: 'admins',   label: 'Admins',   icon: '🛡️', count: users.filter(u =>  u.is_superuser).length },
            { id: 'insights', label: 'Insights', icon: '📊', count: null },
            { id: 'settings', label: 'Settings', icon: '⚙️', count: null },
          ].map(tab => (
            <button
              key={tab.id}
              className="admin-nav-item"
              style={{ ...s.navItem, ...(activeTab === tab.id ? s.navItemActive : {}) }}
              onClick={() => { setActiveTab(tab.id as any); setFilter('all'); }}
            >
              <span>{tab.icon}</span>
              <span style={{ flex: 1 }}>{tab.label}</span>
              {tab.count !== null && <span style={s.navCount}>{tab.count}</span>}
            </button>
          ))}
        </nav>

      </aside>

      {/* ── Main content ── */}
      <main style={s.main} className="admin-main">
        {/* Header */}
        <div style={s.mainHeader} className="admin-header">
          <div>
            <h1 style={s.pageTitle}>
              {activeTab === 'clients' ? 'Client Accounts' : activeTab === 'admins' ? 'Admin Accounts' : activeTab === 'insights' ? 'Insights & Analytics' : 'Account Settings'}
            </h1>
            <p style={s.pageDesc}>
              {activeTab === 'clients'
                ? `${users.filter(u => !u.is_superuser).length} registered clients`
                : activeTab === 'admins'
                ? `${users.filter(u => u.is_superuser).length} administrators`
                : activeTab === 'insights'
                ? 'Platform activity overview'
                : 'Manage your personal admin profile'}
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 20 }} className="admin-header-actions">
            <button style={s.refreshBtn} onClick={fetchAll}>↻ Refresh</button>
            <div style={{ width: 1, height: 24, background: '#1e293b' }} />
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={s.adminAvatar}>{adminInfo?.username?.charAt(0).toUpperCase() ?? 'A'}</div>
              <div>
                <div style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>{adminInfo?.username ?? 'Admin'}</div>
                <div 
                  style={{ color: '#475569', fontSize: 11, cursor: 'pointer', transition: 'color 0.2s', fontWeight: 600 }} 
                  onClick={logout}
                  onMouseEnter={e => e.currentTarget.style.color = '#f87171'}
                  onMouseLeave={e => e.currentTarget.style.color = '#475569'}
                >
                  Sign Out ↩
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ── Insights Tab ── */}
        {activeTab === 'insights' && insights && <InsightsView data={insights} />}

        {/* ── Settings Tab ── */}
        {activeTab === 'settings' && adminInfo && (
          <SettingsView adminInfo={adminInfo} setAdminInfo={setAdminInfo} toast$={toast$} />
        )}

        {/* Stats */}
        {(activeTab === 'clients' || activeTab === 'admins') && (
          <div style={s.statsRow} className="admin-stats">
            {[
              { label: 'Total Users',   val: users.length,    color: '#60a5fa', bg: 'rgba(96,165,250,0.08)',   icon: '👥' },
              { label: 'Active',        val: users.filter(u => getActivityStatus(u) === 'Online').length,   color: '#4ade80', bg: 'rgba(74,222,128,0.08)',   icon: '🟢' },
              { label: 'Inactive',      val: users.filter(u => getActivityStatus(u) !== 'Online').length, color: '#f87171', bg: 'rgba(248,113,113,0.08)', icon: '🔴' },
              { label: 'Administrators',val: users.filter(u => u.is_superuser).length,    color: '#fbbf24', bg: 'rgba(251,191,36,0.08)',  icon: '🛡️' },
            ].map(st => (
              <div key={st.label} style={{ ...s.statCard, background: st.bg, borderColor: `${st.color}22` }}>
                <div style={{ fontSize: 24 }}>{st.icon}</div>
                <div style={{ color: st.color, fontSize: 28, fontWeight: 800, lineHeight: 1 }}>{st.val}</div>
                <div style={{ color: '#475569', fontSize: 12, marginTop: 2 }}>{st.label}</div>
              </div>
            ))}
          </div>
        )}

        {/* Controls */}
        {(activeTab === 'clients' || activeTab === 'admins') && (
          <div style={s.controls} className="admin-controls">
            <div style={s.searchWrap} className="admin-search">
              <svg style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)' }} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#475569" strokeWidth="2">
                <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
              </svg>
              <input style={s.searchInput} placeholder={`Search ${activeTab}…`} value={search} onChange={e => setSearch(e.target.value)} />
            </div>
            <div style={s.filters} className="admin-filters">
              {(['all', 'active', 'inactive'] as const).map(f => (
                <button key={f} style={{ ...s.filterBtn, ...(filter === f ? s.filterActive : {}) }} onClick={() => setFilter(f)}>
                  {f.charAt(0).toUpperCase() + f.slice(1)}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Table */}
        {(activeTab === 'clients' || activeTab === 'admins') && (
          <div style={s.tableWrap}>
            <table style={s.table}>
            <thead>
              <tr>
                {['ID', 'User', 'Email', 'Status', 'Role', 'Actions'].map(h => (
                  <th key={h} style={s.th}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '60px 20px', color: '#334155' }}>
                    <div style={{ fontSize: 40, marginBottom: 12 }}>🔍</div>
                    No {activeTab} found{search ? ` matching "${search}"` : ''}.
                  </td>
                </tr>
              ) : filtered.map(u => (
                <tr key={u.id} style={s.row}>
                  <td style={s.td}>
                    <code style={{ color: '#475569', fontSize: 12 }}>#{u.id}</code>
                  </td>
                  <td style={s.td}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <div style={{ ...s.avatar, background: u.is_superuser ? 'linear-gradient(135deg,#dc2626,#7c3aed)' : 'linear-gradient(135deg,#3b82f6,#8b5cf6)' }}>
                        {u.username.charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <div style={{ color: '#e2e8f0', fontWeight: 600, fontSize: 14 }}>{u.username}</div>
                        {u.is_superuser && <span style={s.adminTag}>ADMIN</span>}
                      </div>
                    </div>
                  </td>
                  <td style={s.td}><span style={{ color: '#64748b', fontSize: 13 }}>{u.email}</span></td>
                  <td style={s.td}>
                    {(() => {
                      const status = getActivityStatus(u);
                      let color = '#94a3b8', bg = 'rgba(148,163,184,0.08)', border = '#94a3b833';
                      
                      if (status === 'Disabled') {
                          color = '#f87171'; bg = 'rgba(248,113,113,0.08)'; border = '#f8717133';
                      } else if (status === 'Online') {
                          color = '#4ade80'; bg = 'rgba(74,222,128,0.08)'; border = '#4ade8033';
                      }
                      
                      return (
                        <span style={{ ...s.badge, color, background: bg, borderColor: border }}>
                          ● {status}
                        </span>
                      );
                    })()}
                  </td>
                  <td style={s.td}>
                    <span style={{ ...s.badge, color: u.is_superuser ? '#fbbf24' : '#64748b', background: u.is_superuser ? 'rgba(251,191,36,0.08)' : 'rgba(100,116,139,0.08)', borderColor: u.is_superuser ? '#fbbf2433' : '#64748b33' }}>
                      {u.is_superuser ? '🛡️ Admin' : '👤 User'}
                    </span>
                  </td>
                  <td style={s.td}>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      <button
                        style={{ ...s.actionBtn, color: u.is_active ? '#f87171' : '#4ade80', background: u.is_active ? '#450a0a' : '#052e16' }}
                        onClick={() => toggleActive(u)}
                        disabled={actioning === u.id}
                        title={u.is_active ? 'Disable account' : 'Enable account'}
                      >
                        {actioning === u.id ? '…' : u.is_active ? '🔒 Disable' : '🔓 Enable'}
                      </button>
                      <button
                        style={{ ...s.actionBtn, color: '#fbbf24', background: '#1c1400' }}
                        onClick={() => toggleSuperuser(u)}
                        disabled={actioning === u.id}
                        title={u.is_superuser ? 'Remove admin' : 'Make admin'}
                      >
                        {u.is_superuser ? '⬇ Demote' : '⬆ Admin'}
                      </button>
                      <button
                        style={{ ...s.actionBtn, color: '#f87171', background: '#1c0a0a', border: '1px solid #dc262620' }}
                        onClick={() => setDelTarget(u)}
                        disabled={actioning === u.id}
                        title="Delete permanently"
                      >
                        🗑 Delete
                      </button>
                      <button
                        style={{ ...s.actionBtn, color: '#60a5fa', background: '#172554', border: '1px solid #1e3a8a20' }}
                        onClick={() => fetchUserDetails(u)}
                        disabled={actioning === u.id}
                        title="View Full Details"
                      >
                        👁 Details
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        )}

        {(activeTab === 'clients' || activeTab === 'admins') && (
          <p style={{ color: '#334155', fontSize: 12, marginTop: 12, textAlign: 'right' }}>
            Showing {filtered.length} of {users.filter(u => activeTab === 'admins' ? u.is_superuser : !u.is_superuser).length} {activeTab}
          </p>
        )}

        {/* ── User Details Modal ── */}
        {viewUser && (
          <div style={s.overlay}>
            <div style={{ ...s.modal, maxWidth: 600, maxHeight: '80vh', overflowY: 'auto' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <h2 style={{ margin: 0, color: '#f1f5f9', fontSize: 20 }}>User Details: {viewUser.username}</h2>
                <button onClick={() => setViewUser(null)} style={{ background: 'none', border: 'none', color: '#64748b', fontSize: 24, cursor: 'pointer' }}>×</button>
              </div>

              {!userDetails ? (
                <div style={{ display: 'flex', justifyContent: 'center', padding: '40px 0' }}>
                  <div style={s.spinner} />
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
                  {/* Basic Info */}
                  <div style={{ background: '#0f172a', padding: 16, borderRadius: 8 }}>
                    <h4 style={{ margin: '0 0 12px', color: '#94a3b8' }}>Profile</h4>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 13, color: '#e2e8f0' }} className="user-details-grid">
                      <div><span style={{ color: '#475569' }}>Email:</span> {userDetails.user.email}</div>
                      <div><span style={{ color: '#475569' }}>Created:</span> {formatDate(userDetails.user.created_at)}</div>
                      <div><span style={{ color: '#475569' }}>Role:</span> {userDetails.user.is_superuser ? 'Admin' : 'Client'}</div>
                      <div><span style={{ color: '#475569' }}>Status:</span> {userDetails.user.is_active ? 'Active' : 'Inactive'}</div>
                    </div>
                  </div>

                  {/* Scans */}
                  <div>
                    <h4 style={{ margin: '0 0 12px', color: '#94a3b8' }}>Scans ({userDetails.scans.length})</h4>
                    {userDetails.scans.length === 0 ? <div style={{ fontSize: 13, color: '#475569' }}>No scans recorded</div> : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {userDetails.scans.slice(0, 10).map((scan: any) => (
                          <div key={scan.id} style={{ background: '#020617', padding: '10px 14px', borderRadius: 6, border: '1px solid #1e293b', fontSize: 12 }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                              <strong style={{ color: '#38bdf8' }}>{scan.scan_type}</strong>
                              <span style={{ color: '#64748b' }}>{formatDate(scan.created_at)}</span>
                            </div>
                            <div style={{ color: '#e2e8f0' }}>Target: {scan.target}</div>
                          </div>
                        ))}
                        {userDetails.scans.length > 10 && <div style={{ fontSize: 11, color: '#64748b', textAlign: 'center' }}>+ {userDetails.scans.length - 10} more scans</div>}
                      </div>
                    )}
                  </div>

                  {/* OTPs */}
                  <div>
                    <h4 style={{ margin: '0 0 12px', color: '#94a3b8' }}>OTP History ({userDetails.otps.length})</h4>
                    {userDetails.otps.length === 0 ? <div style={{ fontSize: 13, color: '#475569' }}>No OTPs generated</div> : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {userDetails.otps.slice(0, 5).map((otp: any) => (
                          <div key={otp.id} style={{ background: '#020617', padding: '10px 14px', borderRadius: 6, border: '1px solid #1e293b', fontSize: 12, display: 'flex', justifyContent: 'space-between' }}>
                            <strong style={{ color: '#4ade80' }}>{otp.purpose}</strong>
                            <span style={{ color: '#64748b' }}>{formatDate(otp.created_at)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

      </main>
    </div>
  );
}

/* ─────────────────────── SettingsView Component ────────────────────────── */

function SettingsView({ adminInfo, setAdminInfo, toast$ }: { adminInfo: AdminInfo, setAdminInfo: any, toast$: any }) {
  const [username, setUsername] = useState(adminInfo.username || '');
  const [email, setEmail]       = useState(adminInfo.email || '');
  const [password, setPassword] = useState('');
  const [loading, setLoading]   = useState(false);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const payload: any = {};
      if (username && username !== adminInfo.username) payload.username = username;
      if (email && email !== adminInfo.email) payload.email = email;
      if (password) payload.password = password;

      if (Object.keys(payload).length === 0) {
        toast$('No changes made', true);
        setLoading(false);
        return;
      }

      const res = await adminApi.patch('/admin/me', payload);
      const updatedInfo = { id: res.data.id, username: res.data.username, email: res.data.email };
      
      // Update local storage and state
      localStorage.setItem('admin_info', JSON.stringify(updatedInfo));
      setAdminInfo(updatedInfo);
      setPassword(''); // clear password field
      toast$('Profile updated successfully', true);

    } catch (e: any) {
      toast$(e.response?.data?.detail || 'Failed to update profile', false);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: 500 }}>
      <form onSubmit={handleSave} style={{ background: '#070d1a', border: '1px solid #0f172a', borderRadius: 12, padding: '24px' }}>
        <h3 style={{ color: '#e2e8f0', margin: '0 0 20px', fontSize: 18 }}>Edit Profile</h3>
        
        <div style={{ marginBottom: 16 }}>
          <label style={{ display: 'block', color: '#94a3b8', fontSize: 13, marginBottom: 8 }}>Username</label>
          <input
            style={set.input}
            value={username}
            onChange={e => setUsername(e.target.value)}
            placeholder="Admin username"
            required
          />
        </div>

        <div style={{ marginBottom: 16 }}>
          <label style={{ display: 'block', color: '#94a3b8', fontSize: 13, marginBottom: 8 }}>Email Address</label>
          <input
            style={set.input}
            type="email"
            value={email}
            onChange={e => setEmail(e.target.value)}
            placeholder="admin@example.com"
            required
          />
        </div>

        <div style={{ marginBottom: 24 }}>
          <label style={{ display: 'block', color: '#94a3b8', fontSize: 13, marginBottom: 8 }}>New Password</label>
          <input
            style={set.input}
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="Leave blank to keep current password"
            autoComplete="new-password"
          />
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button type="submit" disabled={loading} style={set.btn}>
            {loading ? 'Saving…' : 'Save Changes'}
          </button>
        </div>
      </form>
    </div>
  );
}

const set: Record<string, React.CSSProperties> = {
  input: {
    width: '100%', padding: '10px 14px', background: '#020617', border: '1px solid #1e293b', 
    borderRadius: 8, color: '#e2e8f0', fontSize: 14, outline: 'none', boxSizing: 'border-box'
  },
  btn: {
    padding: '10px 20px', background: '#dc2626', border: 'none', borderRadius: 8, 
    color: '#fff', fontSize: 14, fontWeight: 600, cursor: 'pointer', transition: 'background 0.2s'
  }
};

/* ─────────────────────── Result Renderer ────────────────────────── */

const renderResult = (result: any): React.ReactNode => {
  if (typeof result === 'string') {
    try {
      result = JSON.parse(result);
    } catch {
      return <div style={{ color: '#e2e8f0', fontSize: 13, lineHeight: '1.6', whiteSpace: 'pre-wrap' }}>{result}</div>;
    }
  }
  
  if (typeof result !== 'object' || result === null) {
    return <div style={{ color: '#e2e8f0', fontSize: 13 }}>{String(result)}</div>;
  }

  // If array, map it
  if (Array.isArray(result)) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {result.map((item, idx) => (
          <div key={idx} style={{ display: 'flex', gap: 8 }}>
            <span style={{ color: '#475569' }}>•</span>
            <div style={{ flex: 1 }}>{renderResult(item)}</div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {Object.entries(result).map(([key, val], idx) => {
        const isObj = typeof val === 'object' && val !== null;
        return (
          <div key={idx} style={{ background: '#020617', padding: '8px 12px', borderRadius: 6, border: '1px solid #1e293b' }}>
            <div style={{ color: '#60a5fa', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', marginBottom: isObj ? 6 : 0, display: isObj ? 'block' : 'inline-block', marginRight: 10 }}>
              {key.replace(/_/g, ' ')}
            </div>
            {isObj ? (
              <div style={{ paddingLeft: 10, borderLeft: '2px solid #1e293b', marginTop: 4 }}>
                {renderResult(val)}
              </div>
            ) : (
              <span style={{ color: '#f1f5f9', fontSize: 13, wordBreak: 'break-all' }}>
                {String(val)}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
};

/* ─────────────────────── InsightsView Component ────────────────────────── */

function InsightsView({ data }: { data: any }) {
  const [logModal, setLogModal] = useState<{ title: string, type: 'scans' | 'otps' | 'users', data: any[] } | null>(null);
  const [loadingLogs, setLoadingLogs] = useState(false);
  const [expandedScanId, setExpandedScanId] = useState<number | null>(null);

  const fetchLogs = async (endpoint: string, title: string, type: 'scans' | 'otps' | 'users') => {
    setExpandedScanId(null);
    setLogModal({ title, type, data: [] });
    setLoadingLogs(true);
    try {
      const res = await adminApi.get(endpoint);
      setLogModal({ title, type, data: res.data });
    } catch (e: any) {
      alert("Failed to load detailed logs");
      setLogModal(null);
    } finally {
      setLoadingLogs(false);
    }
  };

  const scans    = data.scans    || {};
  const otps     = data.otps     || {};
  const users    = data.users    || {};
  const security = data.security || {};

  const maxScanCount = Math.max(1, ...(scans.by_type || []).map((t: any) => t.count));
  const maxDaily     = Math.max(1, ...(scans.daily_last_7_days || []).map((d: any) => d.scans));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* Security Alerts */}
      {(security.high_otp_volume || security.inactive_accounts > 0) && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <h3 style={ins.sectionTitle}>🚨 Security Alerts</h3>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            {security.high_otp_volume && (
              <div style={{ ...ins.alertCard, borderColor: '#dc262640', background: 'rgba(220,38,38,0.06)' }}>
                <span style={{ fontSize: 20 }}>⚠️</span>
                <div>
                  <div style={{ color: '#f87171', fontWeight: 700 }}>High OTP Volume</div>
                  <div style={{ color: '#64748b', fontSize: 12 }}>{security.otp_requests_24h} OTP requests in 24h — possible abuse</div>
                </div>
              </div>
            )}
            {security.inactive_accounts > 0 && (
              <div style={{ ...ins.alertCard, borderColor: '#f59e0b40', background: 'rgba(245,158,11,0.06)' }}>
                <span style={{ fontSize: 20 }}>🔴</span>
                <div>
                  <div style={{ color: '#fbbf24', fontWeight: 700 }}>{security.inactive_accounts} Inactive Accounts</div>
                  <div style={{ color: '#64748b', fontSize: 12 }}>Accounts that are disabled</div>
                </div>
              </div>
            )}
            {security.dormant_accounts > 0 && (
              <div style={{ ...ins.alertCard, borderColor: '#6366f140', background: 'rgba(99,102,241,0.06)' }}>
                <span style={{ fontSize: 20 }}>💤</span>
                <div>
                  <div style={{ color: '#818cf8', fontWeight: 700 }}>{security.dormant_accounts} Dormant Users</div>
                  <div style={{ color: '#64748b', fontSize: 12 }}>Registered but never performed a scan</div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Key Metrics Row */}
      <div>
        <h3 style={ins.sectionTitle}>📈 Key Metrics</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(130px,1fr))', gap: 12 }}>
          {[
            { label: 'Total Scans',     val: scans.total      ?? 0, color: '#60a5fa', icon: '🔍', action: () => fetchLogs('/admin/scans', 'All Scans', 'scans') },
            { label: 'Scans Today',     val: scans.scans_today ?? 0, color: '#4ade80', icon: '📅', action: () => fetchLogs('/admin/scans?today=true', 'Scans Today', 'scans') },
            { label: 'Total OTPs',      val: otps.total       ?? 0, color: '#a78bfa', icon: '🔐', action: () => fetchLogs('/admin/otps', 'All OTPs', 'otps') },
            { label: 'OTPs (24h)',      val: otps.last_24h    ?? 0, color: '#fb923c', icon: '⏱️', action: () => fetchLogs('/admin/otps?last24h=true', 'OTPs in Last 24 Hours', 'otps') },
            { label: 'Total Users',     val: users.total      ?? 0, color: '#34d399', icon: '👥', action: () => fetchLogs('/admin/users', 'All Users', 'users') },
            { label: 'Active Users',    val: users.active     ?? 0, color: '#4ade80', icon: '✅', action: () => fetchLogs('/admin/users', 'Active Users', 'users') },
          ].map(m => (
            <div 
              key={m.label} 
              style={{ ...ins.metricCard, borderColor: `${m.color}22`, cursor: 'pointer', transition: 'transform 0.2s' }}
              onClick={m.action}
              onMouseEnter={e => e.currentTarget.style.transform = 'translateY(-2px)'}
              onMouseLeave={e => e.currentTarget.style.transform = 'translateY(0)'}
            >
              <div style={{ fontSize: 22 }}>{m.icon}</div>
              <div style={{ color: m.color, fontSize: 26, fontWeight: 800 }}>{m.val}</div>
              <div style={{ color: '#475569', fontSize: 11 }}>{m.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Daily Activity Chart (last 7 days) */}
      <div>
        <h3 style={ins.sectionTitle}>📅 Scan Activity — Last 7 Days</h3>
        <div style={ins.chartCard}>
          {(scans.daily_last_7_days || []).length === 0
            ? <p style={{ color: '#334155', textAlign: 'center', padding: 32 }}>No scan data yet</p>
            : (
            <div style={{ display: 'flex', alignItems: 'flex-end', gap: 10, height: 140, padding: '0 8px' }}>
              {(scans.daily_last_7_days || []).map((d: any) => (
                <div 
                  key={d.date} 
                  style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, cursor: d.scans > 0 ? 'pointer' : 'default', transition: 'opacity 0.2s' }}
                  onClick={() => d.scans > 0 && fetchLogs(`/admin/scans?date=${d.date}`, `Scans on ${d.date}`, 'scans')}
                  onMouseEnter={e => e.currentTarget.style.opacity = '0.8'}
                  onMouseLeave={e => e.currentTarget.style.opacity = '1'}
                >
                  <span style={{ color: '#60a5fa', fontSize: 11, fontWeight: 700 }}>{d.scans || ''}</span>
                  <div style={{
                    width: '100%', borderRadius: '4px 4px 0 0',
                    height: `${Math.max(4, (d.scans / maxDaily) * 100)}px`,
                    background: d.scans > 0
                      ? 'linear-gradient(180deg,#3b82f6,#1d4ed8)'
                      : '#1e293b',
                    transition: 'height 0.4s ease',
                  }} />
                  <span style={{ color: '#334155', fontSize: 10, textAlign: 'center' }}>
                    {d.date.slice(5)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Scan Types + Top Scanners */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }} className="admin-insights-grid">

        {/* Scan Types Breakdown */}
        <div>
          <h3 style={ins.sectionTitle}>🔍 Scan Types</h3>
          <div style={ins.chartCard}>
            {(scans.by_type || []).length === 0
              ? <p style={{ color: '#334155', textAlign: 'center', padding: 20, fontSize: 13 }}>No scans yet</p>
              : (scans.by_type || []).map((t: any, i: number) => {
                  const colors = ['#60a5fa','#4ade80','#a78bfa','#fb923c','#f87171','#34d399','#fbbf24','#f472b6'];
                  const pct = Math.round((t.count / maxScanCount) * 100);
                  return (
                    <div 
                      key={t.type} 
                      style={{ marginBottom: 12, cursor: 'pointer' }}
                      onClick={() => fetchLogs(`/admin/scans?scan_type=${t.type}`, `Scan Type: ${t.type.replace(/_/g,' ').toUpperCase()}`, 'scans')}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                        <span style={{ color: '#94a3b8', fontSize: 12, textTransform: 'capitalize' }}>{t.type.replace(/_/g,' ')}</span>
                        <span style={{ color: colors[i % colors.length], fontSize: 12, fontWeight: 700 }}>{t.count}</span>
                      </div>
                      <div style={{ background: '#0f172a', borderRadius: 4, height: 6 }}>
                        <div style={{ background: colors[i % colors.length], borderRadius: 4, height: 6, width: `${pct}%`, transition: 'width 0.5s ease' }} />
                      </div>
                    </div>
                  );
                })}
          </div>
        </div>

        {/* Top Scanners */}
        <div>
          <h3 style={ins.sectionTitle}>🏆 Top Scanners</h3>
          <div style={ins.chartCard}>
            {(scans.top_scanners || []).length === 0
              ? <p style={{ color: '#334155', textAlign: 'center', padding: 20, fontSize: 13 }}>No scan data yet</p>
              : (scans.top_scanners || []).map((u: any, i: number) => (
                <div 
                  key={u.user_id} 
                  style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12, cursor: 'pointer', padding: '6px', borderRadius: '8px', transition: 'background 0.2s' }}
                  onClick={() => fetchLogs(`/admin/scans?user_id=${u.user_id}`, `Scans by ${u.username}`, 'scans')}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <div style={{ width: 28, height: 28, borderRadius: '50%', background: ['#fbbf24','#94a3b8','#cd7c3a','#60a5fa','#a78bfa'][i] + '33', display: 'flex', alignItems: 'center', justifyContent: 'center', color: ['#fbbf24','#94a3b8','#cd7c3a','#60a5fa','#a78bfa'][i], fontSize: 13, fontWeight: 800 }}>
                    {i + 1}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>{u.username}</div>
                    <div style={{ color: '#475569', fontSize: 11 }}>{u.scans} scans</div>
                  </div>
                  <div style={{ color: '#60a5fa', fontWeight: 700, fontSize: 14 }}>{u.scans}</div>
                </div>
              ))}
          </div>
        </div>
      </div>

      {/* OTP Breakdown + Email Domains */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }} className="admin-insights-grid">

        {/* OTP by Purpose */}
        <div>
          <h3 style={ins.sectionTitle}>🔐 OTP Requests by Purpose</h3>
          <div style={ins.chartCard}>
            {(otps.by_purpose || []).length === 0
              ? <p style={{ color: '#334155', textAlign: 'center', padding: 20, fontSize: 13 }}>No OTP data</p>
              : (otps.by_purpose || []).map((o: any) => (
                <div 
                  key={o.purpose} 
                  style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 8px', borderBottom: '1px solid #0f172a', cursor: 'pointer', transition: 'background 0.2s', borderRadius: '4px' }}
                  onClick={() => fetchLogs(`/admin/otps?purpose=${o.purpose}`, `OTP Logs: ${o.purpose.replace(/_/g,' ').toUpperCase()}`, 'otps')}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <span style={{ color: '#94a3b8', fontSize: 13, textTransform: 'capitalize' }}>{o.purpose.replace(/_/g,' ')}</span>
                  <span style={{ background: '#1e293b', color: '#a78bfa', padding: '2px 10px', borderRadius: 20, fontSize: 12, fontWeight: 700 }}>{o.count}</span>
                </div>
              ))}
          </div>
        </div>

        {/* Email Domains */}
        <div>
          <h3 style={ins.sectionTitle}>📧 Top Email Domains</h3>
          <div style={ins.chartCard}>
            {(users.top_email_domains || []).length === 0
              ? <p style={{ color: '#334155', textAlign: 'center', padding: 20, fontSize: 13 }}>No data</p>
              : (users.top_email_domains || []).map((d: any) => (
                <div key={d.domain} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', borderBottom: '1px solid #0f172a' }}>
                  <span style={{ color: '#94a3b8', fontSize: 13 }}>@{d.domain}</span>
                  <span style={{ background: '#1e293b', color: '#34d399', padding: '2px 10px', borderRadius: 20, fontSize: 12, fontWeight: 700 }}>{d.count}</span>
                </div>
              ))}
          </div>
        </div>
      </div>

      <p style={{ color: '#1e293b', fontSize: 11, textAlign: 'right' }}>
        Generated at {formatDate(data.generated_at)}
      </p>

      {/* ── Detailed Logs Modal ── */}
      {logModal && (
        <div style={s.overlay}>
          <div style={{ ...s.modal, maxWidth: 700, maxHeight: '85vh', display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <h2 style={{ margin: 0, color: '#f1f5f9', fontSize: 18, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{logModal.title}</h2>
              <button onClick={() => { setLogModal(null); setExpandedScanId(null); }} style={{ background: 'none', border: 'none', color: '#64748b', fontSize: 24, cursor: 'pointer' }}>×</button>
            </div>

            {loadingLogs ? (
              <div style={{ display: 'flex', justifyContent: 'center', padding: '40px 0' }}><div style={s.spinner} /></div>
            ) : logModal.data.length === 0 ? (
              <p style={{ color: '#64748b', textAlign: 'center', padding: '40px 0' }}>No detailed records found.</p>
            ) : (
              <div style={{ overflowY: 'auto', flex: 1, paddingRight: 4, display: 'flex', flexDirection: 'column', gap: 10 }}>
                {logModal.type === 'scans' ? (
                  logModal.data.map((scan: any) => (
                    <div 
                      key={scan.id} 
                      style={{ background: '#0f172a', padding: 14, borderRadius: 8, border: '1px solid', borderColor: expandedScanId === scan.id ? '#3b82f6' : '#1e293b', cursor: 'pointer', transition: 'border-color 0.2s' }}
                      onClick={() => setExpandedScanId(expandedScanId === scan.id ? null : scan.id)}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                        <strong style={{ color: '#38bdf8', fontSize: 13 }}>{scan.scan_type}</strong>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <span style={{ color: '#64748b', fontSize: 11 }}>{formatDate(scan.created_at)}</span>
                          <span style={{ color: '#94a3b8', fontSize: 10 }}>{expandedScanId === scan.id ? '▲' : '▼'}</span>
                        </div>
                      </div>
                      <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 4 }}>
                        User: <strong style={{ color: '#cbd5e1' }}>{scan.username}</strong>
                      </div>
                      <div style={{ color: '#e2e8f0', fontSize: 12, wordBreak: 'break-all' }}>
                        Target: {scan.target}
                      </div>
                      {expandedScanId === scan.id && scan.result && (
                        <div style={{ marginTop: 12, paddingTop: 12, borderTop: '1px solid #1e293b' }}>
                          <div style={{ color: '#94a3b8', fontSize: 11, marginBottom: 12, textTransform: 'uppercase', fontWeight: 700 }}>Scan Report Data</div>
                          <div style={{ background: '#070d1a', padding: 12, borderRadius: 8 }}>
                            {renderResult(scan.result)}
                          </div>
                        </div>
                      )}
                    </div>
                  ))
                ) : logModal.type === 'users' ? (
                  logModal.data.map((u: any) => {
                    if (logModal.title === 'Active Users' && !u.is_active) return null;
                    return (
                      <div key={u.id} style={{ background: '#0f172a', padding: 14, borderRadius: 8, border: '1px solid #1e293b', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div>
                          <strong style={{ color: '#f8fafc', fontSize: 14 }}>{u.username}</strong>
                          <div style={{ color: '#94a3b8', fontSize: 12 }}>{u.email}</div>
                          {u.last_active && <div style={{ color: '#64748b', fontSize: 11, marginTop: 4 }}>Last Active: {formatDate(u.last_active)}</div>}
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
                          <span style={{ padding: '2px 8px', borderRadius: 12, fontSize: 10, fontWeight: 700, color: u.is_active ? '#4ade80' : '#f87171', background: u.is_active ? 'rgba(74,222,128,0.1)' : 'rgba(248,113,113,0.1)' }}>
                            {u.is_active ? 'ACTIVE' : 'INACTIVE'}
                          </span>
                          <span style={{ padding: '2px 8px', borderRadius: 12, fontSize: 10, fontWeight: 700, color: u.is_superuser ? '#fbbf24' : '#64748b', background: u.is_superuser ? 'rgba(251,191,36,0.1)' : 'rgba(100,116,139,0.1)' }}>
                            {u.is_superuser ? 'ADMIN' : 'USER'}
                          </span>
                        </div>
                      </div>
                    );
                  })
                ) : (
                  logModal.data.map((otp: any) => (
                    <div key={otp.id} style={{ background: '#0f172a', padding: 14, borderRadius: 8, border: '1px solid #1e293b' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                        <strong style={{ color: '#4ade80', fontSize: 13 }}>{otp.purpose}</strong>
                        <span style={{ color: '#64748b', fontSize: 11 }}>{formatDate(otp.created_at)}</span>
                      </div>
                      <div style={{ color: '#94a3b8', fontSize: 12 }}>
                        Sent to: <strong style={{ color: '#cbd5e1' }}>{otp.email}</strong>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

const ins: Record<string, React.CSSProperties> = {
  sectionTitle: { margin: '0 0 12px', fontSize: 13, fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.08em' },
  alertCard:    { display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px', border: '1px solid', borderRadius: 10, flex: 1, minWidth: 200 },
  metricCard:   { border: '1px solid', borderRadius: 12, padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 4, background: '#070d1a' },
  chartCard:    { background: '#070d1a', border: '1px solid #0f172a', borderRadius: 12, padding: '16px 20px' },
};

const s: Record<string, React.CSSProperties> = {
  page:    { display: 'flex', minHeight: '100vh', background: '#020617', fontFamily: 'Inter,Arial,sans-serif', position: 'relative', overflow: 'hidden' },
  gridBg:  { position: 'fixed', inset: 0, backgroundImage: 'linear-gradient(rgba(220,38,38,0.02) 1px,transparent 1px),linear-gradient(90deg,rgba(220,38,38,0.02) 1px,transparent 1px)', backgroundSize: '40px 40px', pointerEvents: 'none' },
  center:  { display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', background: '#020617', gap: 8 },
  spinner: { width: 36, height: 36, border: '3px solid #1e293b', borderTop: '3px solid #dc2626', borderRadius: '50%', animation: 'spin 0.8s linear infinite' },

  /* Sidebar */
  sidebar: { width: 240, background: '#070d1a', borderRight: '1px solid #0f172a', display: 'flex', flexDirection: 'column', padding: '24px 16px', flexShrink: 0, position: 'sticky', top: 0, height: '100vh', overflowY: 'auto' },
  brand:     { display: 'flex', alignItems: 'center', gap: 12, marginBottom: 32 },
  brandIcon: { width: 40, height: 40, borderRadius: 10, background: 'rgba(220,38,38,0.1)', border: '1px solid rgba(220,38,38,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 },
  brandName: { color: '#f1f5f9', fontSize: 16, fontWeight: 700 },
  brandSub:  { color: '#334155', fontSize: 11, marginTop: 1 },
  nav:       { display: 'flex', flexDirection: 'column', gap: 4, flex: 1 },
  navItem:   { display: 'flex', alignItems: 'center', gap: 10, padding: '10px 12px', borderRadius: 8, border: 'none', background: 'none', color: '#475569', fontSize: 14, cursor: 'pointer', textAlign: 'left', transition: 'all 0.15s' },
  navItemActive: { background: 'rgba(220,38,38,0.1)', color: '#f87171', borderLeft: '2px solid #dc2626' },
  navCount:  { background: '#0f172a', color: '#64748b', borderRadius: 20, fontSize: 11, padding: '1px 7px', fontWeight: 600 },
  adminAvatar: { width: 34, height: 34, borderRadius: '50%', background: 'linear-gradient(135deg,#dc2626,#7c3aed)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontWeight: 700, fontSize: 14, flexShrink: 0 },

  /* Main */
  main:       { flex: 1, padding: '32px 28px', overflowY: 'auto' },
  mainHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24, flexWrap: 'wrap', gap: 12 },
  pageTitle:  { margin: 0, fontSize: 24, fontWeight: 700, color: '#f1f5f9', letterSpacing: '-0.5px' },
  pageDesc:   { margin: '4px 0 0', color: '#475569', fontSize: 13 },
  refreshBtn: { padding: '8px 16px', background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, color: '#64748b', cursor: 'pointer', fontSize: 13 },

  /* Stats */
  statsRow: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(140px,1fr))', gap: 14, marginBottom: 24 },
  statCard: { border: '1px solid', borderRadius: 12, padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: 6 },

  /* Controls */
  controls:    { display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' },
  searchWrap:  { position: 'relative', flex: 1, minWidth: 200 },
  searchInput: { width: '100%', padding: '9px 12px 9px 36px', background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, color: '#e2e8f0', fontSize: 14, outline: 'none', boxSizing: 'border-box' },
  filters:     { display: 'flex', gap: 6 },
  filterBtn:   { padding: '8px 14px', background: '#0f172a', border: '1px solid #1e293b', borderRadius: 6, color: '#64748b', cursor: 'pointer', fontSize: 13 },
  filterActive:{ background: 'rgba(220,38,38,0.1)', borderColor: '#dc2626', color: '#f87171' },

  /* Table */
  tableWrap: { background: '#070d1a', border: '1px solid #0f172a', borderRadius: 12, overflow: 'auto' },
  table:     { width: '100%', borderCollapse: 'collapse' },
  th:        { padding: '13px 16px', textAlign: 'left', color: '#334155', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', borderBottom: '1px solid #0f172a', background: '#020617' },
  row:       { borderBottom: '1px solid #0a0f1e', transition: 'background 0.1s' },
  td:        { padding: '13px 16px', verticalAlign: 'middle' },
  avatar:    { width: 34, height: 34, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontWeight: 700, fontSize: 14, flexShrink: 0 },
  adminTag:  { display: 'inline-block', background: 'rgba(220,38,38,0.15)', color: '#dc2626', fontSize: 9, fontWeight: 800, padding: '1px 5px', borderRadius: 3, letterSpacing: '0.08em', marginTop: 2 },
  badge:     { display: 'inline-block', padding: '3px 10px', borderRadius: 20, fontSize: 12, fontWeight: 600, border: '1px solid' },
  actionBtn: { padding: '5px 10px', borderRadius: 6, border: 'none', cursor: 'pointer', fontSize: 12, fontWeight: 600, whiteSpace: 'nowrap', transition: 'opacity 0.15s' },

  /* Modal */
  overlay:   { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999 },
  modal:     { background: '#070d1a', border: '1px solid #1e293b', borderRadius: 14, padding: '32px 28px', maxWidth: 380, width: '90%' },
  outlineBtn:{ flex: 1, padding: '10px', background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, color: '#94a3b8', cursor: 'pointer', fontWeight: 600, fontSize: 14 },
  redBtn:    { flex: 1, padding: '10px', background: '#dc2626', border: 'none', borderRadius: 8, color: '#fff', cursor: 'pointer', fontWeight: 700, fontSize: 14 },

  /* Toast */
  toast: { position: 'fixed', top: 20, right: 20, padding: '12px 20px', borderRadius: 8, color: '#fff', fontWeight: 600, fontSize: 14, zIndex: 99999, boxShadow: '0 4px 20px rgba(0,0,0,0.5)' },
};
