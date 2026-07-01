
import { useState, useEffect } from 'react';
import { Card } from '../../components/Card';
import { Button } from '../../components/Button';
import { 
    Download, FileText, AlertTriangle, CheckCircle, FileJson, 
    History, Database, BarChart3, Shield, Activity
} from 'lucide-react';
import { api } from '../../services/api';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

interface HistoryItem {
    id: number;
    scan_type: string;
    target: string;
    result: string;
    created_at: string;
}

const scanTypeColors: Record<string, string> = {
    'URL_AGGRESSIVE_SCAN': '#3b82f6',
    'IP_COMPREHENSIVE_SCAN': '#8b5cf6',
    'IP_CHECK': '#a855f7',
    'FILE_INTEGRITY': '#06b6d4',
    'METADATA_SCAN': '#eab308',
    'EMAIL_HEADERS': '#f59e0b',
    'SECURITY_HEADERS': '#10b981',
    'PHISHING_CHECK': '#ef4444',
    'PASSWORD_STRENGTH': '#f97316',
    'CODE_SCAN': '#6366f1',
    'RANSOMWARE_SCAN': '#ec4899',
    'BROWSER_EXTENSIONS': '#a855f7',
};

export const ReportsExporter = () => {
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<string | null>(null);
    const [history, setHistory] = useState<HistoryItem[]>([]);
    const [loadingHistory, setLoadingHistory] = useState(true);

    useEffect(() => {
        fetchHistory();
    }, []);

    const fetchHistory = async () => {
        try {
            const response = await api.get('/history');
            setHistory(response.data);
        } catch (err) {
            console.error('Failed to fetch history:', err);
        } finally {
            setLoadingHistory(false);
        }
    };

    const getScanTypeName = (scanType: string): string => {
        const typeMap: Record<string, string> = {
            'URL_AGGRESSIVE_SCAN': 'URL Scan',
            'IP_COMPREHENSIVE_SCAN': 'IP Scan',
            'IP_CHECK': 'IP Check',
            'FILE_INTEGRITY': 'File Integrity',
            'METADATA_SCAN': 'Metadata',
            'EMAIL_HEADERS': 'Email Headers',
            'SECURITY_HEADERS': 'Security Headers',
            'PHISHING_CHECK': 'Phishing Check',
            'PASSWORD_STRENGTH': 'Password Strength',
            'CODE_SCAN': 'Code Scan',
            'RANSOMWARE_SCAN': 'Ransomware Scan',
            'BROWSER_EXTENSIONS': 'Extensions',
        };
        return typeMap[scanType] || scanType.replace(/_/g, ' ');
    };

    // Compute scan type distribution
    const scanTypeCounts = history.reduce((acc, item) => {
        acc[item.scan_type] = (acc[item.scan_type] || 0) + 1;
        return acc;
    }, {} as Record<string, number>);

    const sortedTypes = Object.entries(scanTypeCounts).sort((a, b) => b[1] - a[1]);
    const maxCount = sortedTypes.length > 0 ? sortedTypes[0][1] : 0;

    // Recent activity (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const recentScans = history.filter(h => new Date(h.created_at) >= sevenDaysAgo).length;

    // Unique types used
    const uniqueTypes = new Set(history.map(h => h.scan_type)).size;

    const handleExportPDF = async () => {
        setLoading(true);
        setError(null);
        setSuccess(null);
        try {
            const doc = new jsPDF();
            const pageWidth = doc.internal.pageSize.getWidth();
            let yPos = 20;
            doc.setFontSize(22);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(40, 40, 40);
            doc.text('Genesis Security Report', pageWidth / 2, yPos, { align: 'center' });
            yPos += 10;
            doc.setFontSize(12);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(100, 100, 100);
            doc.text('Complete Scan History Export', pageWidth / 2, yPos, { align: 'center' });
            yPos += 8;
            doc.setFontSize(10);
            doc.setTextColor(150, 150, 150);
            doc.text(`Generated: ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}`, pageWidth / 2, yPos, { align: 'center' });
            yPos += 15;
            doc.setDrawColor(200, 200, 200);
            doc.line(20, yPos, pageWidth - 20, yPos);
            yPos += 10;
            doc.setFontSize(14);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(40, 40, 40);
            doc.text('Summary Statistics', 20, yPos);
            yPos += 8;

            const scanTypes = [...new Set(history.map(h => h.scan_type))];
            const summaryData = scanTypes.map(type => [
                getScanTypeName(type),
                history.filter(h => h.scan_type === type).length.toString()
            ]);
            summaryData.push(['Total Scans', history.length.toString()]);

            autoTable(doc, {
                startY: yPos,
                head: [['Scan Type', 'Count']],
                body: summaryData,
                theme: 'striped',
                headStyles: { fillColor: [59, 130, 246] },
                margin: { left: 20, right: 20 },
            });
            yPos = (doc as any).lastAutoTable.finalY + 15;

            if (yPos > 200) { doc.addPage(); yPos = 20; }
            doc.setFontSize(14);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(40, 40, 40);
            doc.text('Scan History', 20, yPos);
            yPos += 8;

            const historyData = history.map(item => [
                new Date(item.created_at).toLocaleDateString('en-IN'),
                getScanTypeName(item.scan_type),
                item.target.substring(0, 40) + (item.target.length > 40 ? '...' : '')
            ]);

            autoTable(doc, {
                startY: yPos,
                head: [['Date', 'Type', 'Target']],
                body: historyData,
                theme: 'striped',
                headStyles: { fillColor: [59, 130, 246] },
                margin: { left: 20, right: 20 },
                styles: { fontSize: 8 },
            });

            const pageCount = doc.getNumberOfPages();
            for (let i = 1; i <= pageCount; i++) {
                doc.setPage(i);
                doc.setFontSize(8);
                doc.setTextColor(150, 150, 150);
                doc.text(`Genesis Security Dashboard - Page ${i} of ${pageCount}`, pageWidth / 2, doc.internal.pageSize.getHeight() - 10, { align: 'center' });
            }
            doc.save(`genesis_security_report_${new Date().toISOString().split('T')[0]}.pdf`);
            setSuccess('PDF report exported successfully!');
        } catch (err: any) { setError(err.message); }
        finally { setLoading(false); }
    };

    const handleExportCSV = async () => {
        setLoading(true); setError(null); setSuccess(null);
        try {
            const headers = ['ID', 'Date', 'Time', 'Scan Type', 'Target'];
            const rows = history.map(item => {
                const date = new Date(item.created_at);
                return [item.id.toString(), date.toLocaleDateString('en-IN'), date.toLocaleTimeString('en-IN'), getScanTypeName(item.scan_type), `"${item.target.replace(/"/g, '""')}"`].join(',');
            });
            const csv = [headers.join(','), ...rows].join('\n');
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `genesis_scan_history_${new Date().toISOString().split('T')[0]}.csv`;
            document.body.appendChild(a); a.click();
            window.URL.revokeObjectURL(url); document.body.removeChild(a);
            setSuccess('CSV report exported successfully!');
        } catch (err: any) { setError(err.message); }
        finally { setLoading(false); }
    };

    const handleExportJSON = async () => {
        setLoading(true); setError(null); setSuccess(null);
        try {
            const exportData = {
                exportedAt: new Date().toISOString(),
                totalScans: history.length,
                scans: history.map(item => ({
                    id: item.id, type: item.scan_type,
                    typeName: getScanTypeName(item.scan_type),
                    target: item.target, timestamp: item.created_at,
                    result: JSON.parse(item.result || '{}')
                }))
            };
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `genesis_scan_history_${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a); a.click();
            window.URL.revokeObjectURL(url); document.body.removeChild(a);
            setSuccess('JSON report exported successfully!');
        } catch (err: any) { setError(err.message); }
        finally { setLoading(false); }
    };

    return (
        <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
            {/* Page Header */}
            <div className="page-header">
                <div className="page-header-icon" style={{ background: 'hsl(var(--color-success-light))', color: 'hsl(var(--color-success))' }}>
                    <Download size={28} />
                </div>
                <div className="page-header-content">
                    <h1>Export Reports</h1>
                    <p>Download your scan history and security reports in multiple formats</p>
                </div>
            </div>

            {/* ROW 1: Stats overview */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.75rem', marginBottom: '1.5rem' }}>
                <Card>
                    <div style={{ textAlign: 'center', padding: '0.5rem 0' }}>
                        <Database size={22} style={{ color: 'hsl(var(--color-primary))', marginBottom: '0.25rem' }} />
                        <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Total Scans</p>
                        <p style={{ fontSize: '2rem', fontWeight: 900, color: 'hsl(var(--color-primary))' }}>
                            {loadingHistory ? '...' : history.length}
                        </p>
                    </div>
                </Card>
                <Card>
                    <div style={{ textAlign: 'center', padding: '0.5rem 0' }}>
                        <Shield size={22} style={{ color: 'hsl(var(--color-success))', marginBottom: '0.25rem' }} />
                        <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Scan Types</p>
                        <p style={{ fontSize: '2rem', fontWeight: 900, color: 'hsl(var(--color-success))' }}>
                            {uniqueTypes}
                        </p>
                    </div>
                </Card>
                <Card>
                    <div style={{ textAlign: 'center', padding: '0.5rem 0' }}>
                        <Activity size={22} style={{ color: '#f97316', marginBottom: '0.25rem' }} />
                        <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Last 7 Days</p>
                        <p style={{ fontSize: '2rem', fontWeight: 900, color: '#f97316' }}>
                            {recentScans}
                        </p>
                    </div>
                </Card>
                <Card>
                    <div style={{ textAlign: 'center', padding: '0.5rem 0' }}>
                        <History size={22} style={{ color: 'hsl(var(--color-info))', marginBottom: '0.25rem' }} />
                        <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>First Scan</p>
                        <p style={{ fontSize: '0.85rem', fontWeight: 900, color: 'hsl(var(--color-info))' }}>
                            {history.length > 0 ? new Date(history[history.length - 1].created_at).toLocaleDateString('en-IN') : '—'}
                        </p>
                    </div>
                </Card>
            </div>

            {/* ROW 2: Scan Type Distribution */}
            {sortedTypes.length > 0 && (
                <Card title="Scan Distribution" style={{ marginBottom: '1.5rem' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                        {sortedTypes.map(([type, count]) => (
                            <div key={type} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                <span style={{ 
                                    width: '100px', fontSize: '0.75rem', fontWeight: 600, 
                                    color: 'hsl(var(--text-secondary))', textAlign: 'right', flexShrink: 0
                                }}>
                                    {getScanTypeName(type)}
                                </span>
                                <div style={{ flex: 1, height: '18px', background: 'hsl(var(--bg-secondary))', borderRadius: '4px', overflow: 'hidden' }}>
                                    <div style={{
                                        height: '100%',
                                        width: `${(count / maxCount) * 100}%`,
                                        background: scanTypeColors[type] || 'hsl(var(--color-primary))',
                                        borderRadius: '4px',
                                        transition: 'width 0.5s ease',
                                        display: 'flex', alignItems: 'center', justifyContent: 'flex-end', paddingRight: '0.5rem'
                                    }}>
                                        {count > 2 && (
                                            <span style={{ fontSize: '0.6rem', fontWeight: 700, color: 'white' }}>{count}</span>
                                        )}
                                    </div>
                                </div>
                                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'hsl(var(--text-primary))', width: '32px' }}>
                                    {count}
                                </span>
                            </div>
                        ))}
                    </div>
                </Card>
            )}

            {/* ROW 3: Export Options */}
            <Card title="Export Formats" style={{ marginBottom: '1.5rem' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem' }}>
                    {/* PDF */}
                    <div style={{
                        padding: '1.25rem', borderRadius: 'var(--radius-lg)',
                        background: 'hsla(0, 85%, 50%, 0.04)',
                        border: '1px solid hsla(0, 85%, 50%, 0.12)',
                        display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', gap: '0.5rem'
                    }}>
                        <div style={{ padding: '0.75rem', borderRadius: '50%', background: 'hsla(0, 85%, 50%, 0.1)' }}>
                            <FileText size={24} style={{ color: 'hsl(0, 85%, 50%)' }} />
                        </div>
                        <h4 style={{ fontWeight: 700, fontSize: '1rem' }}>PDF Report</h4>
                        <p style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))', lineHeight: 1.4 }}>
                            Professional report with summary stats &amp; complete history
                        </p>
                        <Button onClick={handleExportPDF} isLoading={loading} variant="primary" size="sm" disabled={history.length === 0}>
                            <Download size={14} /> Export PDF
                        </Button>
                    </div>

                    {/* CSV */}
                    <div style={{
                        padding: '1.25rem', borderRadius: 'var(--radius-lg)',
                        background: 'hsla(var(--color-success), 0.04)',
                        border: '1px solid hsla(var(--color-success), 0.12)',
                        display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', gap: '0.5rem'
                    }}>
                        <div style={{ padding: '0.75rem', borderRadius: '50%', background: 'hsla(var(--color-success), 0.1)' }}>
                            <BarChart3 size={24} style={{ color: 'hsl(var(--color-success))' }} />
                        </div>
                        <h4 style={{ fontWeight: 700, fontSize: '1rem' }}>CSV Export</h4>
                        <p style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))', lineHeight: 1.4 }}>
                            Spreadsheet-ready format for Excel &amp; Google Sheets
                        </p>
                        <Button onClick={handleExportCSV} isLoading={loading} variant="outline" size="sm" disabled={history.length === 0}>
                            <Download size={14} /> Export CSV
                        </Button>
                    </div>

                    {/* JSON */}
                    <div style={{
                        padding: '1.25rem', borderRadius: 'var(--radius-lg)',
                        background: 'hsla(var(--color-info), 0.04)',
                        border: '1px solid hsla(var(--color-info), 0.12)',
                        display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', gap: '0.5rem'
                    }}>
                        <div style={{ padding: '0.75rem', borderRadius: '50%', background: 'hsla(var(--color-info), 0.1)' }}>
                            <FileJson size={24} style={{ color: 'hsl(var(--color-info))' }} />
                        </div>
                        <h4 style={{ fontWeight: 700, fontSize: '1rem' }}>JSON Data</h4>
                        <p style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))', lineHeight: 1.4 }}>
                            Raw data with full results for programmatic use
                        </p>
                        <Button onClick={handleExportJSON} isLoading={loading} variant="outline" size="sm" disabled={history.length === 0}>
                            <Download size={14} /> Export JSON
                        </Button>
                    </div>
                </div>
            </Card>

            {/* Error */}
            {error && (
                <div style={{ 
                    padding: '1rem', marginBottom: '1.5rem',
                    background: 'hsl(var(--color-error-light))', 
                    border: '1px solid hsla(var(--color-error), 0.3)', 
                    borderRadius: 'var(--radius-lg)', color: 'hsl(var(--color-error))', fontWeight: 600,
                    display: 'flex', alignItems: 'center', gap: '0.75rem'
                }}>
                    <AlertTriangle size={20} />
                    {error}
                </div>
            )}

            {/* Success */}
            {success && (
                <div style={{ 
                    padding: '1rem', marginBottom: '1.5rem',
                    background: 'hsl(var(--color-success-light))', 
                    border: '1px solid hsla(var(--color-success), 0.3)', 
                    borderRadius: 'var(--radius-lg)', color: 'hsl(var(--color-success))', fontWeight: 600,
                    display: 'flex', alignItems: 'center', gap: '0.75rem'
                }}>
                    <CheckCircle size={20} />
                    {success}
                </div>
            )}
        </div>
    );
};
