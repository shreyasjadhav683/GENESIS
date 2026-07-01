import React, { useState } from 'react';
import { Card } from '../../components/Card';
import { Input } from '../../components/Input';
import { Button } from '../../components/Button';
import { api } from '../../services/api';
import { ScanHistoryTable } from '../../components/ScanHistoryTable';
import { ExportButton } from '../../components/ExportButton';
import { Lock, ShieldCheck, ShieldAlert, History, RefreshCw, AlertTriangle, Zap, Calendar, XCircle } from 'lucide-react';

const gradeColor: Record<string, string> = { A: 'hsl(var(--color-success))', B: 'hsl(142,70%,45%)', C: 'hsl(var(--color-warning))', D: 'hsl(30,90%,55%)', F: 'hsl(var(--color-error))' };

export const SslChecker = () => {
    const [domain, setDomain] = useState('');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<any>(null);
    const [error, setError] = useState<string | null>(null);
    const [showHistory, setShowHistory] = useState(false);

    const handleCheck = async (e: React.FormEvent) => {
        e.preventDefault();
        const d = domain.trim();
        if (!d) return;
        setLoading(true); setError(null); setResult(null);
        try {
            const res = await api.get(`/scan/ssl-check?domain=${encodeURIComponent(d)}`);
            setResult(res.data);
        } catch (err: any) {
            setError(err.response?.data?.detail || err.message || 'SSL check failed');
        } finally {
            setLoading(false);
        }
    };

    const expiryBarColor = (days: number) => days < 0 ? 'hsl(var(--color-error))' : days < 30 ? 'hsl(var(--color-warning))' : 'hsl(var(--color-success))';

    return (
        <div style={{ maxWidth: '1000px', margin: '0 auto' }}>
            <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div className="page-header-icon" style={{ background: 'hsla(var(--color-success), 0.1)', color: 'hsl(var(--color-success))' }}>
                        <Lock size={28} />
                    </div>
                    <div>
                        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>SSL / TLS Checker</h1>
                        <p style={{ color: 'hsl(var(--text-secondary))', margin: 0, fontSize: '0.9rem' }}>Certificate validity, expiry & chain analysis</p>
                    </div>
                </div>
                <div style={{ position: 'relative' }}>
                    <Button variant="secondary" onClick={() => setShowHistory(!showHistory)} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <History size={18} /> History
                    </Button>
                    {showHistory && (
                        <>
                            <div style={{ position: 'fixed', inset: 0, zIndex: 90 }} onClick={() => setShowHistory(false)} />
                            <div className="animate-fade-in-up" style={{ position: 'absolute', top: 'calc(100% + 10px)', right: 0, width: '860px', maxHeight: '80vh', background: 'hsl(var(--bg-card))', border: '1px solid hsl(var(--border-color))', borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-xl)', zIndex: 100, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                                <div style={{ padding: '1rem', borderBottom: '1px solid hsl(var(--border-color))', background: 'hsl(var(--bg-secondary-light))' }}>
                                    <h3 style={{ fontSize: '0.9rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>SSL Check History</h3>
                                </div>
                                <div style={{ flex: 1, overflow: 'auto', padding: '1rem' }}>
                                    <ScanHistoryTable type="SSL" onDelete={() => {}} />
                                </div>
                            </div>
                        </>
                    )}
                </div>
            </div>

            <Card style={{ marginBottom: '1.5rem' }}>
                <form onSubmit={handleCheck} style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end' }}>
                    <div style={{ flex: 1 }}>
                        <Input label="Domain Name" placeholder="e.g., google.com, github.com (no https://)" value={domain}
                            onChange={(e) => setDomain(e.target.value)} icon={<Lock size={18} />} required />
                    </div>
                    <Button type="submit" isLoading={loading} variant="primary">
                        <Zap size={18} />{loading ? 'Checking...' : 'Check SSL'}
                    </Button>
                </form>
            </Card>

            {error && (
                <div style={{ padding: '1rem', marginBottom: '1.5rem', background: 'hsl(var(--color-error-light))', border: '1px solid hsla(var(--color-error), 0.3)', borderRadius: 'var(--radius-lg)', color: 'hsl(var(--color-error))', display: 'flex', alignItems: 'center', gap: '0.75rem', fontWeight: 600 }}>
                    <AlertTriangle size={20} />{error}
                </div>
            )}

            {result && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
                        <ExportButton getJSONData={() => result} getPDFData={() => ({
                            title: 'SSL/TLS Certificate Report', subtitle: result.domain,
                            summary: {
                                'Domain': result.domain, 'Grade': result.grade || 'N/A',
                                'Valid': result.valid ? 'Yes' : 'No', 'Days Remaining': result.days_remaining ?? 'N/A',
                                'Issued To': result.cert_details?.issued_to_cn || 'N/A',
                                'Issued By': result.cert_details?.issued_by_cn || 'N/A',
                                'Valid From': result.cert_details?.not_before || 'N/A',
                                'Valid Until': result.cert_details?.not_after || 'N/A',
                                'Algorithm': result.cert_details?.signature_algorithm || 'N/A',
                                'SANs': result.cert_details?.san_count ?? 0,
                            },
                            tables: result.cert_details?.sans?.length ? [{ title: 'Subject Alternative Names', headers: ['SAN'], rows: result.cert_details.sans.map((s: string) => [s]) }] : [],
                            flags: result.is_expired ? ['Certificate is EXPIRED'] : [],
                        })} />
                        <Button onClick={() => { setResult(null); setDomain(''); }} variant="secondary" size="sm"><RefreshCw size={16} /> New Check</Button>
                    </div>

                    {result.error && !result.cert_details && (
                        <Card>
                            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem', padding: '2rem' }}>
                                <XCircle size={48} style={{ color: 'hsl(var(--color-error))' }} />
                                <h3 style={{ fontWeight: 700, color: 'hsl(var(--color-error))' }}>SSL Check Failed</h3>
                                <p style={{ color: 'hsl(var(--text-secondary))', textAlign: 'center' }}>{result.error}</p>
                            </div>
                        </Card>
                    )}

                    {result.cert_details && (
                        <>
                            <div style={{ display: 'grid', gridTemplateColumns: '160px 1fr', gap: '1rem' }}>
                                <Card>
                                    <div style={{ textAlign: 'center', padding: '1rem 0' }}>
                                        <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Grade</p>
                                        <p style={{ fontSize: '4rem', fontWeight: 900, lineHeight: 1, marginTop: '0.5rem', color: gradeColor[result.grade] || 'hsl(var(--text-primary))' }}>{result.grade}</p>
                                        <div style={{ marginTop: '0.5rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.4rem' }}>
                                            {result.valid ? <ShieldCheck size={16} style={{ color: 'hsl(var(--color-success))' }} /> : <ShieldAlert size={16} style={{ color: 'hsl(var(--color-error))' }} />}
                                            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: result.valid ? 'hsl(var(--color-success))' : 'hsl(var(--color-error))' }}>{result.valid ? 'VALID' : 'INVALID'}</span>
                                        </div>
                                    </div>
                                </Card>
                                <Card>
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                                        <div>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                                                <span style={{ fontSize: '0.8rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.4rem' }}><Calendar size={14} />Expiry Status</span>
                                                <span style={{ fontWeight: 800, color: expiryBarColor(result.days_remaining ?? 0) }}>{result.days_remaining !== null ? `${result.days_remaining} days remaining` : 'Unknown'}</span>
                                            </div>
                                            <div style={{ height: '8px', background: 'hsl(var(--bg-tertiary))', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
                                                <div style={{ height: '100%', width: `${Math.min(100, Math.max(0, (result.days_remaining ?? 0) / 365 * 100))}%`, background: expiryBarColor(result.days_remaining ?? 0), borderRadius: 'var(--radius-full)', transition: 'width 0.5s ease' }} />
                                            </div>
                                        </div>
                                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                                            {[
                                                { label: 'Issued To', value: result.cert_details.issued_to_cn },
                                                { label: 'Issued By', value: result.cert_details.issued_by_cn },
                                                { label: 'Valid From', value: result.cert_details.not_before ? new Date(result.cert_details.not_before).toLocaleDateString() : 'N/A' },
                                                { label: 'Valid Until', value: result.cert_details.not_after ? new Date(result.cert_details.not_after).toLocaleDateString() : 'N/A' },
                                            ].map((item, i) => (
                                                <div key={i} style={{ padding: '0.4rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)' }}>
                                                    <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>{item.label}</p>
                                                    <p style={{ fontSize: '0.8rem', fontWeight: 600, fontFamily: 'monospace' }}>{item.value || 'N/A'}</p>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </Card>
                            </div>

                            <Card title="Certificate Details">
                                <table className="data-table">
                                    <tbody>
                                        {[
                                            { label: 'Subject Org', value: result.cert_details.issued_to_org },
                                            { label: 'CA Organization', value: result.cert_details.issued_by_org },
                                            { label: 'Algorithm', value: result.cert_details.signature_algorithm },
                                            { label: 'Version', value: result.cert_details.version },
                                            { label: 'Serial Number', value: result.cert_details.serial_number },
                                            { label: 'SAN Count', value: String(result.cert_details.san_count) },
                                        ].map((row, i) => (
                                            <tr key={i}><td style={{ fontWeight: 600, width: '35%' }}>{row.label}</td><td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{row.value || 'N/A'}</td></tr>
                                        ))}
                                    </tbody>
                                </table>
                            </Card>

                            {result.cert_details.sans?.length > 0 && (
                                <Card title={`Subject Alternative Names (${result.cert_details.san_count})`}>
                                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                                        {result.cert_details.sans.map((san: string, i: number) => (
                                            <span key={i} style={{ padding: '0.2rem 0.6rem', background: 'hsl(var(--bg-secondary))', border: '1px solid hsl(var(--border-color))', borderRadius: 'var(--radius-sm)', fontSize: '0.75rem', fontFamily: 'monospace', color: san.startsWith('*.') ? 'hsl(var(--color-warning))' : 'hsl(var(--text-secondary))' }}>{san}</span>
                                        ))}
                                    </div>
                                </Card>
                            )}
                        </>
                    )}
                </div>
            )}
        </div>
    );
};
