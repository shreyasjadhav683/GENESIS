import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

interface UserRecord {
  id: number;
  username: string;
  email: string;
  is_active: boolean;
  is_superuser: boolean;
  security_question: string;
}

interface Stats {
  total_users: number;
  active_users: number;
  inactive_users: number;
  admin_users: number;
}

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
  const [adminInfo] = useState<AdminInfo | null>(() => {
    try { return JSON.parse(localStorage.getItem('admin_info') || 'null'); }
    catch { return null; }
  });

  const [users, setUsers]         = useState<UserRecord[]>([]);
  const [stats, setStats]         = useState<Stats | null>(null);
  const [loading, setLoading]     = useState(true);
  const [actioning, setActioning] = useState<number | null>(null);
  const [error, setError]         = useState('');
  const [search, setSearch]       = useState('');
  const [filter, setFilter]       = useState<'all' | 'active' | 'inactive' | 'admin'>('all');
  const [toast, setToast]         = useState<{ msg: string; ok: boolean } | null>(null);
  const [delTarget, setDelTarget] = useState<UserRecord | null>(null);
  const [activeTab, setActiveTab] = useState<'clients' | 'admins'>('clients');

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
      const [u, s] = await Promise.all([
        adminApi.get('/admin/users'),
        adminApi.get('/admin/stats'),
      ]);
      setUsers(u.data);
      setStats(s.data);
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

  const logout = () => {
    localStorage.removeItem('admin_token');
    localStorage.removeItem('admin_info');
    navigate('/admin-login', { replace: true });
  };

  /* ── Filtered view ── */
  const filtered = users.filter(u => {
    const q = search.toLowerCase();
    const matchSearch = !q || u.username.toLowerCase().includes(q) || u.email.toLowerCase().includes(q);
    const matchFilter =
      filter === 'all'      ? true :
      filter === 'active'   ? u.is_active :
      filter === 'inactive' ? !u.is_active :
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
    <div style={s.page}>
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
      <aside style={s.sidebar}>
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

        <nav style={s.nav}>
          {[
            { id: 'clients', label: 'Clients', icon: '👥', count: users.filter(u => !u.is_superuser).length },
            { id: 'admins',  label: 'Admins',  icon: '🛡️', count: users.filter(u =>  u.is_superuser).length },
          ].map(tab => (
            <button
              key={tab.id}
              style={{ ...s.navItem, ...(activeTab === tab.id ? s.navItemActive : {}) }}
              onClick={() => { setActiveTab(tab.id as any); setFilter('all'); }}
            >
              <span>{tab.icon}</span>
              <span style={{ flex: 1 }}>{tab.label}</span>
              <span style={s.navCount}>{tab.count}</span>
            </button>
          ))}
        </nav>

        {/* Admin info */}
        <div style={s.adminCard}>
          <div style={s.adminAvatar}>{adminInfo?.username?.charAt(0).toUpperCase() ?? 'A'}</div>
          <div>
            <div style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>{adminInfo?.username ?? 'Admin'}</div>
            <div style={{ color: '#475569', fontSize: 11 }}>{adminInfo?.email}</div>
          </div>
        </div>
        <button style={s.logoutBtn} onClick={logout}>↩ Sign Out</button>
      </aside>

      {/* ── Main content ── */}
      <main style={s.main}>
        {/* Header */}
        <div style={s.mainHeader}>
          <div>
            <h1 style={s.pageTitle}>{activeTab === 'clients' ? 'Client Accounts' : 'Admin Accounts'}</h1>
            <p style={s.pageDesc}>
              {activeTab === 'clients'
                ? `${users.filter(u => !u.is_superuser).length} registered clients`
                : `${users.filter(u => u.is_superuser).length} administrators`}
            </p>
          </div>
          <button style={s.refreshBtn} onClick={fetchAll}>↻ Refresh</button>
        </div>

        {/* Stats */}
        {stats && (
          <div style={s.statsRow}>
            {[
              { label: 'Total Users',   val: stats.total_users,    color: '#60a5fa', bg: 'rgba(96,165,250,0.08)',   icon: '👥' },
              { label: 'Active',        val: stats.active_users,   color: '#4ade80', bg: 'rgba(74,222,128,0.08)',   icon: '🟢' },
              { label: 'Inactive',      val: stats.inactive_users, color: '#f87171', bg: 'rgba(248,113,113,0.08)', icon: '🔴' },
              { label: 'Administrators',val: stats.admin_users,    color: '#fbbf24', bg: 'rgba(251,191,36,0.08)',  icon: '🛡️' },
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
        <div style={s.controls}>
          <div style={s.searchWrap}>
            <svg style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)' }} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#475569" strokeWidth="2">
              <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
            </svg>
            <input style={s.searchInput} placeholder={`Search ${activeTab}…`} value={search} onChange={e => setSearch(e.target.value)} />
          </div>
          <div style={s.filters}>
            {(['all', 'active', 'inactive'] as const).map(f => (
              <button key={f} style={{ ...s.filterBtn, ...(filter === f ? s.filterActive : {}) }} onClick={() => setFilter(f)}>
                {f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {/* Table */}
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
                    <span style={{ ...s.badge, color: u.is_active ? '#4ade80' : '#f87171', background: u.is_active ? 'rgba(74,222,128,0.08)' : 'rgba(248,113,113,0.08)', borderColor: u.is_active ? '#4ade8033' : '#f8717133' }}>
                      ● {u.is_active ? 'Active' : 'Inactive'}
                    </span>
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
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <p style={{ color: '#334155', fontSize: 12, marginTop: 12, textAlign: 'right' }}>
          Showing {filtered.length} of {users.filter(u => activeTab === 'admins' ? u.is_superuser : !u.is_superuser).length} {activeTab}
        </p>
      </main>
    </div>
  );
}

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
  adminCard: { display: 'flex', alignItems: 'center', gap: 10, padding: '12px', background: '#0f172a', borderRadius: 10, marginTop: 'auto', marginBottom: 8 },
  adminAvatar: { width: 32, height: 32, borderRadius: '50%', background: 'linear-gradient(135deg,#dc2626,#7c3aed)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontWeight: 700, fontSize: 14, flexShrink: 0 },
  logoutBtn: { width: '100%', padding: '8px', background: 'none', border: '1px solid #1e293b', borderRadius: 8, color: '#475569', cursor: 'pointer', fontSize: 13 },

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
