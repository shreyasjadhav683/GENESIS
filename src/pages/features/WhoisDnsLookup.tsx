import React, { useState } from 'react';
import { Card } from '../../components/Card';
import { Input } from '../../components/Input';
import { Button } from '../../components/Button';
import { api } from '../../services/api';
import { ScanHistoryTable } from '../../components/ScanHistoryTable';
import { ExportButton } from '../../components/ExportButton';
import {
    Globe, Server, History, RefreshCw, AlertTriangle,
    Zap
} from 'lucide-react';

const TAB_WHOIS = 'whois';
const TAB_DNS = 'dns';

// ----------------------------- WHOIS Result
const WhoisResult = ({ result }: { result: any }) => {
    const expiring = result.days_until_expiry !== null && result.days_until_expiry < 30;
    const expired = result.is_expired;

    const statusColor = expired ? 'hsl(var(--color-error))' : expiring ? 'hsl(var(--color-warning))' : 'hsl(var(--color-success))';
    const statusBg = expired ? 'hsl(var(--color-error-light))' : expiring ? 'hsl(var(--color-warning-light))' : 'hsl(var(--color-success-light))';

    const infoRows = [
        { label: 'Registrar', value: result.registrar },
        { label: 'WHOIS Server', value: result.whois_server },
        { label: 'Organization', value: result.org },
        { label: 'Country', value: result.country },
        { label: 'State / City', value: [result.state, result.city].filter(Boolean).join(', ') || null },
        { label: 'DNSSEC', value: result.dnssec },
        { label: 'Registrant', value: result.name },
    ].filter(r => r.value);

    return (
        <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Header stat cards */}
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
                            {expired ? 'EXPIRED' : expiring ? 'EXPIRING SOON' : 'ACTIVE'}
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
                {/* Registration Info */}
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

                {/* Name Servers */}
                <Card title="Name Servers">
                    {result.name_servers?.length > 0 ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            {result.name_servers.map((ns: string, i: number) => (
                                <div key={i} style={{
                                    padding: '0.5rem 0.75rem',
                                    background: 'hsl(var(--bg-secondary))',
                                    borderRadius: 'var(--radius-md)',
                                    fontFamily: 'monospace',
                                    fontSize: '0.8rem',
                                    display: 'flex', alignItems: 'center', gap: '0.5rem'
                                }}>
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

            {/* Status Flags */}
            {result.status?.length > 0 && (
                <Card title="Domain Status Flags">
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                        {result.status.map((s: string, i: number) => (
                            <span key={i} style={{
                                padding: '0.2rem 0.6rem',
                                background: 'hsla(var(--color-info), 0.1)',
                                border: '1px solid hsla(var(--color-info), 0.2)',
                                color: 'hsl(var(--color-info))',
                                borderRadius: 'var(--radius-sm)',
                                fontSize: '0.7rem', fontWeight: 600, fontFamily: 'monospace'
                            }}>
                                {s.split(' ')[0]}
                            </span>
                        ))}
                    </div>
                </Card>
            )}
        </div>
    );
};

// ----------------------------- DNS Result
const DNS_COLORS: Record<string, { bg: string; text: string }> = {
    A:     { bg: 'hsla(var(--color-primary), 0.1)',   text: 'hsl(var(--color-primary))' },
    AAAA:  { bg: 'hsla(var(--color-secondary), 0.1)', text: 'hsl(var(--color-secondary))' },
    MX:    { bg: 'hsla(var(--color-warning), 0.1)',   text: 'hsl(var(--color-warning))' },
    NS:    { bg: 'hsla(var(--color-info), 0.1)',      text: 'hsl(var(--color-info))' },
    TXT:   { bg: 'hsla(155, 60%, 40%, 0.1)',          text: 'hsl(155, 60%, 40%)' },
    CNAME: { bg: 'hsla(280, 60%, 60%, 0.1)',          text: 'hsl(280, 60%, 60%)' },
    SOA:   { bg: 'hsla(var(--color-error), 0.07)',    text: 'hsl(var(--color-error))' },
};

const DnsResult = ({ result }: { result: any }) => {
    const { records, summary } = result;
    const recordTypes = Object.keys(records).filter(t => records[t]?.length > 0);

    return (
        <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Summary stats */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.75rem' }}>
                {[
                    { label: 'A Records', value: summary.total_a_records, color: 'hsl(var(--color-primary))' },
                    { label: 'MX Records', value: summary.total_mx_records, color: 'hsl(var(--color-warning))' },
                    { label: 'NS Records', value: summary.total_ns_records, color: 'hsl(var(--color-info))' },
                    { label: 'TXT Records', value: summary.total_txt_records, color: 'hsl(155, 60%, 40%)' },
                ].map((item, i) => (
                    <Card key={i}>
                        <div style={{ textAlign: 'center', padding: '0.5rem 0' }}>
                            <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>{item.label}</p>
                            <p style={{ fontSize: '2rem', fontWeight: 900, color: item.color, marginTop: '0.25rem' }}>{item.value}</p>
                        </div>
                    </Card>
                ))}
            </div>

            {/* Record type cards */}
            {recordTypes.map(rtype => {
                const color = DNS_COLORS[rtype] || { bg: 'hsl(var(--bg-secondary))', text: 'hsl(var(--text-secondary))' };
                const recs = records[rtype];

                return (
                    <Card key={rtype} title={`${rtype} — ${recs.length} record${recs.length !== 1 ? 's' : ''}`}
                        style={{ borderLeft: `3px solid ${color.text}` }}>
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
                <Card>
                    <p style={{ textAlign: 'center', padding: '2rem', color: 'hsl(var(--text-muted))' }}>No DNS records found for this domain.</p>
                </Card>
            )}
        </div>
    );
};

// ----------------------------- Main Component
export const WhoisDnsLookup = () => {
    const [tab, setTab] = useState<'whois' | 'dns'>(TAB_WHOIS);
    const [domain, setDomain] = useState('');
    const [loading, setLoading] = useState(false);
    const [whoisResult, setWhoisResult] = useState<any>(null);
    const [dnsResult, setDnsResult] = useState<any>(null);
    const [error, setError] = useState<string | null>(null);
    const [showHistory, setShowHistory] = useState(false);

    const handleLookup = async (e: React.FormEvent) => {
        e.preventDefault();
        const d = domain.trim();
        if (!d) return;
        setLoading(true);
        setError(null);
        try {
            if (tab === TAB_WHOIS) {
                const res = await api.get(`/whois-dns/whois?domain=${encodeURIComponent(d)}`);
                setWhoisResult(res.data);
            } else {
                const res = await api.get(`/whois-dns/dns?domain=${encodeURIComponent(d)}`);
                setDnsResult(res.data);
            }
        } catch (err: any) {
            setError(err.response?.data?.detail || err.message || 'Lookup failed');
        } finally {
            setLoading(false);
        }
    };

    const activeResult = tab === TAB_WHOIS ? whoisResult : dnsResult;

    return (
        <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
            {/* Page Header */}
            <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div className="page-header-icon" style={{ background: 'hsla(var(--color-info), 0.1)', color: 'hsl(var(--color-info))' }}>
                        <Globe size={28} />
                    </div>
                    <div>
                        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>WHOIS & DNS Lookup</h1>
                        <p style={{ color: 'hsl(var(--text-secondary))', margin: 0, fontSize: '0.9rem' }}>Domain registration & DNS record analysis</p>
                    </div>
                </div>
                <div style={{ position: 'relative' }}>
                    <Button variant="secondary" onClick={() => setShowHistory(!showHistory)} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <History size={18} />
                        History
                    </Button>
                    {showHistory && (
                        <>
                            <div style={{ position: 'fixed', inset: 0, zIndex: 90 }} onClick={() => setShowHistory(false)} />
                            <div className="animate-fade-in-up" style={{
                                position: 'absolute', top: 'calc(100% + 10px)', right: 0, width: '900px',
                                maxHeight: '80vh', background: 'hsl(var(--bg-card))',
                                border: '1px solid hsl(var(--border-color))', borderRadius: 'var(--radius-lg)',
                                boxShadow: 'var(--shadow-xl)', zIndex: 100, display: 'flex', flexDirection: 'column', overflow: 'hidden'
                            }}>
                                <div style={{ padding: '1rem', borderBottom: '1px solid hsl(var(--border-color))', background: 'hsl(var(--bg-secondary-light))' }}>
                                    <h3 style={{ fontSize: '0.9rem', fontWeight: 700, color: 'hsl(var(--text-primary))', textTransform: 'uppercase', letterSpacing: '0.05em' }}>WHOIS & DNS History</h3>
                                </div>
                                <div style={{ flex: 1, overflow: 'auto', padding: '1rem' }}>
                                    <ScanHistoryTable type="WHOIS_DNS" onDelete={() => {}} />
                                </div>
                            </div>
                        </>
                    )}
                </div>
            </div>

            {/* Tab Switcher */}
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem' }}>
                {([TAB_WHOIS, TAB_DNS] as const).map(t => (
                    <button
                        key={t}
                        onClick={() => { setTab(t); setError(null); }}
                        style={{
                            padding: '0.6rem 1.5rem',
                            borderRadius: 'var(--radius-md)',
                            fontWeight: 700,
                            fontSize: '0.85rem',
                            cursor: 'pointer',
                            border: `2px solid ${tab === t ? 'hsl(var(--color-info))' : 'hsl(var(--border-color))'}`,
                            background: tab === t ? 'hsla(var(--color-info), 0.1)' : 'transparent',
                            color: tab === t ? 'hsl(var(--color-info))' : 'hsl(var(--text-secondary))',
                            transition: 'all 0.2s ease',
                        }}
                    >
                        {t === TAB_WHOIS ? '🔍 WHOIS Lookup' : '🌐 DNS Records'}
                    </button>
                ))}
            </div>

            {/* Input Form */}
            <Card style={{ marginBottom: '1.5rem' }}>
                <form onSubmit={handleLookup} style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end' }}>
                    <div style={{ flex: 1 }}>
                        <Input
                            label={tab === TAB_WHOIS ? 'Domain Name' : 'Domain Name'}
                            placeholder={tab === TAB_WHOIS ? 'e.g., google.com, github.com' : 'e.g., example.com, amazon.com'}
                            value={domain}
                            onChange={(e) => setDomain(e.target.value)}
                            icon={<Globe size={18} />}
                            required
                        />
                    </div>
                    <Button type="submit" isLoading={loading} variant="primary">
                        <Zap size={18} />
                        {loading ? 'Looking up...' : tab === TAB_WHOIS ? 'WHOIS Lookup' : 'DNS Lookup'}
                    </Button>
                </form>
            </Card>

            {/* Error */}
            {error && (
                <div style={{
                    padding: '1rem', marginBottom: '1.5rem',
                    background: 'hsl(var(--color-error-light))', border: '1px solid hsla(var(--color-error), 0.3)',
                    borderRadius: 'var(--radius-lg)', color: 'hsl(var(--color-error))',
                    display: 'flex', alignItems: 'center', gap: '0.75rem', fontWeight: 600
                }}>
                    <AlertTriangle size={20} />
                    {error}
                </div>
            )}

            {/* Export + reset */}
            {activeResult && (
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginBottom: '1rem' }}>
                    <ExportButton getJSONData={() => activeResult} getPDFData={() => {
                        const exportSummary: Record<string, string | number> = {};
                        const exportTables: Array<{ title: string; headers: string[]; rows: string[][] }> = [];
                        const exportFlags: string[] = [];
                        if (tab === TAB_WHOIS) {
                            const r = activeResult as any;
                            exportSummary['Domain'] = r.domain;
                            exportSummary['Registrar'] = r.registrar || 'N/A';
                            exportSummary['Created'] = r.creation_date ? new Date(r.creation_date).toLocaleDateString() : 'N/A';
                            exportSummary['Expires'] = r.expiration_date ? new Date(r.expiration_date).toLocaleDateString() : 'N/A';
                            exportSummary['Days Until Expiry'] = r.days_until_expiry ?? 'N/A';
                            exportSummary['Status'] = r.is_expired ? 'EXPIRED' : 'ACTIVE';
                            exportSummary['Organization'] = r.org || 'N/A';
                            exportSummary['Country'] = r.country || 'N/A';
                            exportSummary['Name Servers'] = (r.name_servers || []).join(', ') || 'N/A';
                            if (r.is_expired) exportFlags.push('Domain is EXPIRED');
                        } else {
                            const r = activeResult as any;
                            exportSummary['Domain'] = r.domain;
                            exportSummary['A Records'] = r.summary?.total_a_records ?? 0;
                            exportSummary['MX Records'] = r.summary?.total_mx_records ?? 0;
                            exportSummary['NS Records'] = r.summary?.total_ns_records ?? 0;
                            exportSummary['TXT Records'] = r.summary?.total_txt_records ?? 0;
                            exportSummary['Has IPv6'] = r.summary?.has_ipv6 ? 'Yes' : 'No';
                            exportSummary['Has CNAME'] = r.summary?.has_cname ? 'Yes' : 'No';
                            Object.entries(r.records || {}).forEach(([type, recs]: [string, any]) => {
                                if (!recs?.length) return;
                                exportTables.push({ title: `${type} Records`, headers: ['Value', 'Extra'], rows: recs.map((rec: any) => [typeof rec === 'string' ? rec : (rec.value || rec.exchange || rec.mname || JSON.stringify(rec)), String(rec.ttl || rec.preference || '')] as [string, string]) });
                            });
                        }
                        return { title: tab === TAB_WHOIS ? 'WHOIS Lookup Report' : 'DNS Lookup Report', subtitle: String((activeResult as any).domain || ''), summary: exportSummary, tables: exportTables, flags: exportFlags };
                    }} />
                    <Button onClick={() => { setWhoisResult(null); setDnsResult(null); setDomain(''); }} variant="secondary" size="sm">
                        <RefreshCw size={16} /> New Lookup
                    </Button>
                </div>
            )}

            {/* Results */}
            {tab === TAB_WHOIS && whoisResult && <WhoisResult result={whoisResult} />}
            {tab === TAB_DNS && dnsResult && <DnsResult result={dnsResult} />}
        </div>
    );
};
