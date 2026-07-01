
import { useState } from 'react';
import { Card } from '../../components/Card';
import { Button } from '../../components/Button';
import { FileUpload } from '../../components/FileUpload';
import { api } from '../../services/api'; 
import { ScanHistoryTable } from '../../components/ScanHistoryTable';
import { ExportButton } from '../../components/ExportButton';
import { 
    ShieldCheck, ShieldAlert, FileSearch, 
    AlertTriangle, FileCheck, RefreshCw, GitCompare, CheckCircle, XCircle, HardDrive, Hash, Clock, History
} from 'lucide-react';

type TabType = 'integrity' | 'compare';

const getStatusColor = (status: string) => {
    switch(status) {
        case 'MODIFIED': case 'ERROR': case 'DIFFERENT': return 'hsl(var(--color-error))';
        case 'NEW': return 'hsl(var(--color-info))';
        case 'IDENTICAL': case 'CLEAN': return 'hsl(var(--color-success))';
        default: return 'hsl(var(--color-warning))';
    }
};

const getStatusBg = (status: string) => {
    switch(status) {
        case 'MODIFIED': case 'ERROR': case 'DIFFERENT': return 'hsla(var(--color-error), 0.06)';
        case 'NEW': return 'hsla(var(--color-info), 0.06)';
        case 'IDENTICAL': case 'CLEAN': return 'hsla(var(--color-success), 0.06)';
        default: return 'hsla(var(--color-warning), 0.06)';
    }
};

const getGradeForStatus = (status: string) => {
    switch(status) {
        case 'CLEAN': case 'IDENTICAL': return { grade: '✓', label: 'Verified' };
        case 'NEW': return { grade: 'N', label: 'New File' };
        case 'MODIFIED': return { grade: '!', label: 'Modified' };
        case 'DIFFERENT': return { grade: '≠', label: 'Different' };
        default: return { grade: '?', label: status };
    }
};

const formatBytes = (bytes: number): string => {
    if (!bytes) return 'N/A';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
};

export const FileIntegrity = () => {
    const [activeTab, setActiveTab] = useState<TabType>('integrity');
    const [file, setFile] = useState<File | null>(null);
    const [hashResult, setHashResult] = useState<any>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [file1, setFile1] = useState<File | null>(null);
    const [file2, setFile2] = useState<File | null>(null);
    const [compareResult, setCompareResult] = useState<any>(null);
    const [compareLoading, setCompareLoading] = useState(false);
    const [compareError, setCompareError] = useState<string | null>(null);
    const [showHistory, setShowHistory] = useState(false);

    const handleFileUpload = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!file) { setError("Please upload a file first"); return; }
        setLoading(true); setError(null); setHashResult(null);
        try {
            const formData = new FormData();
            formData.append('file', file);
            const response = await api.post('/files/integrity', formData, { headers: { 'Content-Type': 'multipart/form-data' } });
            setHashResult(response.data);
        } catch (err: any) {
            setError(err.response?.data?.detail || err.message || 'Failed to analyze file');
        } finally { setLoading(false); }
    };

    const handleCompareFiles = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!file1 || !file2) { setCompareError("Please upload both files to compare"); return; }
        setCompareLoading(true); setCompareError(null); setCompareResult(null);
        try {
            const formData = new FormData();
            formData.append('file1', file1);
            formData.append('file2', file2);
            const response = await api.post('/files/compare', formData, { headers: { 'Content-Type': 'multipart/form-data' } });
            setCompareResult(response.data);
        } catch (err: any) {
            setCompareError(err.response?.data?.detail || err.message || 'Failed to compare files');
        } finally { setCompareLoading(false); }
    };

    const resetCompare = () => { setFile1(null); setFile2(null); setCompareResult(null); setCompareError(null); };

    return (
        <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
            {/* Page Header */}
            <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div className="page-header-icon" style={{ background: 'hsla(var(--color-primary), 0.1)', color: 'hsl(var(--color-primary))' }}>
                        <FileCheck size={28} />
                    </div>
                    <div>
                        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>File Integrity Monitor</h1>
                        <p style={{ color: 'hsl(var(--text-secondary))', margin: 0, fontSize: '0.9rem' }}>Verify file hashes, detect modifications &amp; compare files side-by-side</p>
                    </div>
                </div>
                <div style={{ position: 'relative' }}>
                    <Button 
                        variant="secondary" 
                        onClick={() => setShowHistory(!showHistory)}
                        style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                    >
                        <History size={18} />
                        History
                    </Button>

                    {/* History Popover */}
                    {showHistory && (
                        <>
                            {/* Backdrop for outside click */}
                            <div 
                                style={{ position: 'fixed', inset: 0, zIndex: 90 }} 
                                onClick={() => setShowHistory(false)}
                            />
                            
                            <div 
                                className="animate-fade-in-up"
                                style={{ 
                                    position: 'absolute',
                                    top: 'calc(100% + 10px)',
                                    right: 0,
                                    width: '900px',
                                    maxHeight: '80vh',
                                    background: 'hsl(var(--bg-card))',
                                    border: '1px solid hsl(var(--border-color))',
                                    borderRadius: 'var(--radius-lg)',
                                    boxShadow: 'var(--shadow-xl)',
                                    zIndex: 100,
                                    display: 'flex',
                                    flexDirection: 'column',
                                    overflow: 'hidden'
                                }}
                            >
                                <div style={{ 
                                    padding: '1rem',
                                    borderBottom: '1px solid hsl(var(--border-color))',
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'space-between',
                                    background: 'hsl(var(--bg-secondary-light))'
                                }}>
                                    <h3 style={{ 
                                        fontSize: '0.9rem', 
                                        fontWeight: 700, 
                                        color: 'hsl(var(--text-primary))',
                                        textTransform: 'uppercase',
                                        letterSpacing: '0.05em'
                                    }}>
                                        Start new scan or view history
                                    </h3>
                                </div>
                                <div style={{ flex: 1, overflow: 'auto', padding: '1rem' }}>
                                    <ScanHistoryTable type="FILE" onDelete={() => {}} />
                                </div>
                            </div>
                        </>
                    )}
                </div>
            </div>

            {/* Tab Navigation */}
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem', borderBottom: '1px solid hsl(var(--border-color))', paddingBottom: '1rem' }}>
                <button onClick={() => setActiveTab('integrity')} style={{
                    display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.75rem 1.25rem',
                    background: activeTab === 'integrity' ? 'hsl(var(--color-primary))' : 'hsl(var(--bg-secondary))',
                    color: activeTab === 'integrity' ? '#0a0a12' : 'hsl(var(--text-secondary))',
                    border: 'none', borderRadius: 'var(--radius-lg)', fontWeight: 600, cursor: 'pointer', transition: 'all 0.2s'
                }}>
                    <FileCheck size={18} /> Hash Check
                </button>
                <button onClick={() => setActiveTab('compare')} style={{
                    display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.75rem 1.25rem',
                    background: activeTab === 'compare' ? 'hsl(var(--color-primary))' : 'hsl(var(--bg-secondary))',
                    color: activeTab === 'compare' ? '#0a0a12' : 'hsl(var(--text-secondary))',
                    border: 'none', borderRadius: 'var(--radius-lg)', fontWeight: 600, cursor: 'pointer', transition: 'all 0.2s'
                }}>
                    <GitCompare size={18} /> Compare Files
                </button>
            </div>

            {/* INTEGRITY TAB */}
            {activeTab === 'integrity' && (
                <>
                    {error && (
                        <div style={{ padding: '1rem', background: 'hsl(var(--color-error-light))', border: '1px solid hsla(var(--color-error), 0.3)', borderRadius: 'var(--radius-lg)', color: 'hsl(var(--color-error))', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
                            <AlertTriangle size={20} /> {error}
                        </div>
                    )}

                    <Card style={{ marginBottom: '1.5rem' }}>
                        <form onSubmit={handleFileUpload} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                            <FileUpload label="Upload File to Hash" currentFile={file} onFileSelect={setFile} />
                            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                                <Button type="submit" isLoading={loading} disabled={!file} variant="primary">
                                    <FileSearch size={18} /> Check Integrity
                                </Button>
                            </div>
                        </form>
                    </Card>

                    {hashResult && (
                        <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                            {/* Actions */}
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                    {hashResult.status === 'CLEAN' && <ShieldCheck size={24} style={{ color: getStatusColor(hashResult.status) }} />}
                                    {hashResult.status === 'NEW' && <FileSearch size={24} style={{ color: getStatusColor(hashResult.status) }} />}
                                    {(hashResult.status === 'MODIFIED' || hashResult.status === 'ERROR') && <ShieldAlert size={24} style={{ color: getStatusColor(hashResult.status) }} />}
                                    <span style={{ fontWeight: 700, color: getStatusColor(hashResult.status) }}>
                                        {hashResult.status === 'CLEAN' ? 'File Integrity Verified' : hashResult.status === 'NEW' ? 'New File — Baseline Created' : 'File Has Been Modified'}
                                    </span>
                                </div>
                                <div style={{ display: 'flex', gap: '0.5rem' }}>
                                    <ExportButton 
                                        getPDFData={() => ({
                                            title: 'File Integrity Report',
                                            subtitle: hashResult.filename,
                                            summary: {
                                                'Target': hashResult.filename, 'Scan Type': 'File Integrity',
                                                'Date': new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
                                                'Status': hashResult.status, 'Details': hashResult.details || '',
                                            },
                                            tables: [{
                                                title: 'File Details', headers: ['Property', 'Value'],
                                                rows: [
                                                    ['Filename', hashResult.filename || 'N/A'],
                                                    ['File Size', formatBytes(hashResult.size_bytes)],
                                                    ['Current SHA-256', hashResult.hash || 'N/A'],
                                                    ['Current MD5', hashResult.md5 || 'N/A'],
                                                    ['Baseline SHA-256', hashResult.baseline_hash || 'N/A'],
                                                    ['Algorithm', 'SHA-256'],
                                                ]
                                            }],
                                            flags: hashResult.status === 'MODIFIED' ? ['File has been modified since last scan'] : []
                                        })}
                                        getJSONData={() => hashResult}
                                    />
                                    <Button onClick={() => { setHashResult(null); setFile(null); }} variant="secondary" size="sm">
                                        <RefreshCw size={16} /> New Check
                                    </Button>
                                </div>
                            </div>

                            {/* Grade + Stats */}
                            <div style={{ display: 'grid', gridTemplateColumns: '160px 1fr', gap: '1.5rem' }}>
                                <Card>
                                    <div style={{ textAlign: 'center', padding: '0.75rem 0' }}>
                                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Status</p>
                                        <p style={{ fontSize: '3.5rem', fontWeight: 900, lineHeight: 1, color: getStatusColor(hashResult.status) }}>
                                            {getGradeForStatus(hashResult.status).grade}
                                        </p>
                                        <p style={{ marginTop: '0.5rem', padding: '0.15rem 0.5rem', borderRadius: 'var(--radius-full)', display: 'inline-block', fontSize: '0.65rem', fontWeight: 800, background: `${getStatusColor(hashResult.status)}15`, color: getStatusColor(hashResult.status) }}>
                                            {getGradeForStatus(hashResult.status).label}
                                        </p>
                                    </div>
                                </Card>

                                <Card>
                                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem', marginBottom: '0.75rem' }}>
                                        <div style={{ padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                                            <HardDrive size={16} style={{ color: 'hsl(var(--text-muted))', marginBottom: '0.25rem' }} />
                                            <p style={{ fontSize: '0.55rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>File Size</p>
                                            <p style={{ fontSize: '1rem', fontWeight: 900, color: 'hsl(var(--color-primary))' }}>{formatBytes(hashResult.size_bytes)}</p>
                                        </div>
                                        <div style={{ padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                                            <Hash size={16} style={{ color: 'hsl(var(--text-muted))', marginBottom: '0.25rem' }} />
                                            <p style={{ fontSize: '0.55rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Algorithm</p>
                                            <p style={{ fontSize: '1rem', fontWeight: 900, color: 'hsl(var(--text-primary))' }}>SHA-256</p>
                                        </div>
                                        <div style={{ padding: '0.5rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                                            <Clock size={16} style={{ color: 'hsl(var(--text-muted))', marginBottom: '0.25rem' }} />
                                            <p style={{ fontSize: '0.55rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Scanned</p>
                                            <p style={{ fontSize: '0.72rem', fontWeight: 700, color: 'hsl(var(--text-primary))' }}>
                                                {new Date(hashResult.scan_time).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}
                                            </p>
                                        </div>
                                    </div>
                                    {/* Status Message */}
                                    <div style={{ padding: '0.6rem 0.75rem', borderRadius: 'var(--radius-md)', background: getStatusBg(hashResult.status), border: `1px solid ${getStatusColor(hashResult.status)}15` }}>
                                        <p style={{ fontSize: '0.82rem', color: 'hsl(var(--text-primary))' }}>{hashResult.details}</p>
                                    </div>
                                </Card>
                            </div>

                            {/* Hash Table */}
                            <Card title="Hash Details">
                                <table className="data-table">
                                    <thead><tr><th style={{ width: '30%' }}>Property</th><th>Value</th></tr></thead>
                                    <tbody>
                                        <tr><td style={{ fontWeight: 600 }}>Filename</td><td style={{ fontFamily: 'monospace' }}>{hashResult.filename}</td></tr>
                                        <tr>
                                            <td style={{ fontWeight: 600 }}>Current SHA-256</td>
                                            <td style={{ fontFamily: 'monospace', fontSize: '0.72rem', wordBreak: 'break-all', color: hashResult.status === 'MODIFIED' ? 'hsl(var(--color-error))' : 'hsl(var(--color-primary))' }}>
                                                {hashResult.hash}
                                            </td>
                                        </tr>
                                        {hashResult.md5 && (
                                            <tr>
                                                <td style={{ fontWeight: 600 }}>Current MD5</td>
                                                <td style={{ fontFamily: 'monospace', fontSize: '0.72rem', wordBreak: 'break-all', color: 'hsl(var(--text-secondary))' }}>{hashResult.md5}</td>
                                            </tr>
                                        )}
                                        <tr>
                                            <td style={{ fontWeight: 600 }}>Baseline SHA-256</td>
                                            <td style={{ fontFamily: 'monospace', fontSize: '0.72rem', wordBreak: 'break-all', color: 'hsl(var(--text-secondary))' }}>
                                                {hashResult.baseline_hash || <span style={{ color: 'hsl(var(--text-muted))', fontStyle: 'italic' }}>No previous baseline</span>}
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                            </Card>
                        </div>
                    )}
                </>
            )}

            {/* COMPARE TAB */}
            {activeTab === 'compare' && (
                <>
                    {compareError && (
                        <div style={{ padding: '1rem', background: 'hsl(var(--color-error-light))', border: '1px solid hsla(var(--color-error), 0.3)', borderRadius: 'var(--radius-lg)', color: 'hsl(var(--color-error))', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
                            <AlertTriangle size={20} /> {compareError}
                        </div>
                    )}

                    {!compareResult && (
                        <Card style={{ marginBottom: '1.5rem' }}>
                            <form onSubmit={handleCompareFiles}>
                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.5rem', marginBottom: '1.5rem' }}>
                                    <div style={{ padding: '1rem', border: '2px dashed hsl(var(--color-primary))', borderRadius: 'var(--radius-lg)', background: 'hsla(var(--color-primary), 0.03)' }}>
                                        <h4 style={{ marginBottom: '1rem', color: 'hsl(var(--color-primary))', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                            <span style={{ width: '24px', height: '24px', borderRadius: 'var(--radius-full)', background: 'hsl(var(--color-primary))', color: '#0a0a12', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '0.75rem' }}>1</span>
                                            First File
                                        </h4>
                                        <FileUpload label="Upload first file" currentFile={file1} onFileSelect={setFile1} />
                                    </div>
                                    <div style={{ padding: '1rem', border: '2px dashed hsl(var(--color-secondary))', borderRadius: 'var(--radius-lg)', background: 'hsla(var(--color-secondary), 0.03)' }}>
                                        <h4 style={{ marginBottom: '1rem', color: 'hsl(var(--color-secondary))', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                            <span style={{ width: '24px', height: '24px', borderRadius: 'var(--radius-full)', background: 'hsl(var(--color-secondary))', color: '#0a0a12', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '0.75rem' }}>2</span>
                                            Second File
                                        </h4>
                                        <FileUpload label="Upload second file" currentFile={file2} onFileSelect={setFile2} />
                                    </div>
                                </div>
                                <div style={{ display: 'flex', justifyContent: 'center' }}>
                                    <Button type="submit" isLoading={compareLoading} disabled={!file1 || !file2} variant="primary" size="lg">
                                        <GitCompare size={20} /> Compare Files
                                    </Button>
                                </div>
                            </form>
                        </Card>
                    )}

                    {compareResult && (
                        <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                            {/* Actions */}
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                    {compareResult.status === 'IDENTICAL' && <CheckCircle size={28} style={{ color: getStatusColor(compareResult.status) }} />}
                                    {compareResult.status === 'MODIFIED' && <ShieldAlert size={28} style={{ color: getStatusColor(compareResult.status) }} />}
                                    {compareResult.status === 'DIFFERENT' && <XCircle size={28} style={{ color: getStatusColor(compareResult.status) }} />}
                                    <span style={{ fontWeight: 700, fontSize: '1.1rem', color: getStatusColor(compareResult.status) }}>{compareResult.status}</span>
                                </div>
                                <div style={{ display: 'flex', gap: '0.5rem' }}>
                                    <ExportButton 
                                        getPDFData={() => ({
                                            title: 'File Comparison Report',
                                            subtitle: `${compareResult.file1.filename} vs ${compareResult.file2.filename}`,
                                            summary: {
                                                'Target': `${compareResult.file1.filename} vs ${compareResult.file2.filename}`,
                                                'Scan Type': 'File Comparison',
                                                'Date': new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
                                                'Status': compareResult.status,
                                                'Hashes Match': compareResult.hashes_match ? 'Yes' : 'No',
                                            },
                                            tables: [
                                                { title: 'File 1', headers: ['Property', 'Value'], rows: [['Filename', compareResult.file1.filename], ['Size', formatBytes(compareResult.file1.size_bytes)], ['SHA-256', compareResult.file1.sha256]] },
                                                { title: 'File 2', headers: ['Property', 'Value'], rows: [['Filename', compareResult.file2.filename], ['Size', formatBytes(compareResult.file2.size_bytes)], ['SHA-256', compareResult.file2.sha256]] },
                                            ],
                                            flags: !compareResult.hashes_match ? ['Files have different content'] : []
                                        })}
                                        getJSONData={() => compareResult}
                                    />
                                    <Button onClick={resetCompare} variant="secondary" size="sm">
                                        <RefreshCw size={16} /> New Comparison
                                    </Button>
                                </div>
                            </div>

                            {/* Grade + Match Stats */}
                            <div style={{ display: 'grid', gridTemplateColumns: '160px 1fr', gap: '1.5rem' }}>
                                <Card>
                                    <div style={{ textAlign: 'center', padding: '0.75rem 0' }}>
                                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Result</p>
                                        <p style={{ fontSize: '3.5rem', fontWeight: 900, lineHeight: 1, color: getStatusColor(compareResult.status) }}>
                                            {getGradeForStatus(compareResult.status).grade}
                                        </p>
                                        <p style={{ marginTop: '0.5rem', padding: '0.15rem 0.5rem', borderRadius: 'var(--radius-full)', display: 'inline-block', fontSize: '0.65rem', fontWeight: 800, background: `${getStatusColor(compareResult.status)}15`, color: getStatusColor(compareResult.status) }}>
                                            {getGradeForStatus(compareResult.status).label}
                                        </p>
                                    </div>
                                </Card>

                                <Card>
                                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem', marginBottom: '0.75rem' }}>
                                        <div style={{ padding: '0.6rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                                            <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Hash Match</p>
                                            <p style={{ fontSize: '1.25rem', fontWeight: 900, color: compareResult.hashes_match ? 'hsl(var(--color-success))' : 'hsl(var(--color-error))' }}>
                                                {compareResult.hashes_match ? '✓ YES' : '✗ NO'}
                                            </p>
                                        </div>
                                        <div style={{ padding: '0.6rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                                            <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Size Match</p>
                                            <p style={{ fontSize: '1.25rem', fontWeight: 900, color: compareResult.sizes_match ? 'hsl(var(--color-success))' : 'hsl(var(--color-warning))' }}>
                                                {compareResult.sizes_match ? '✓ YES' : '✗ NO'}
                                            </p>
                                        </div>
                                        <div style={{ padding: '0.6rem 0.75rem', background: 'hsl(var(--bg-secondary))', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                                            <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Size Diff</p>
                                            <p style={{ fontSize: '0.9rem', fontWeight: 900, color: 'hsl(var(--text-primary))' }}>
                                                {compareResult.comparison.size_difference_bytes.toLocaleString()} B
                                            </p>
                                            <p style={{ fontSize: '0.6rem', color: 'hsl(var(--text-muted))' }}>({compareResult.comparison.size_difference_percent}%)</p>
                                        </div>
                                    </div>
                                    <div style={{ padding: '0.6rem 0.75rem', borderRadius: 'var(--radius-md)', background: getStatusBg(compareResult.status), border: `1px solid ${getStatusColor(compareResult.status)}15` }}>
                                        <p style={{ fontSize: '0.82rem', color: 'hsl(var(--text-primary))' }}>{compareResult.details}</p>
                                    </div>
                                </Card>
                            </div>

                            {/* Side by Side */}
                            <Card title="Detailed Comparison">
                                <div style={{ overflowX: 'auto' }}>
                                    <table className="data-table">
                                        <thead>
                                            <tr>
                                                <th style={{ width: '20%' }}>Property</th>
                                                <th style={{ width: '40%', color: 'hsl(var(--color-primary))' }}>File 1: {compareResult.file1.filename}</th>
                                                <th style={{ width: '40%', color: 'hsl(var(--color-secondary))' }}>File 2: {compareResult.file2.filename}</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr>
                                                <td style={{ fontWeight: 600 }}>Size</td>
                                                <td>{compareResult.file1.size_bytes.toLocaleString()} bytes</td>
                                                <td style={{ color: !compareResult.sizes_match ? 'hsl(var(--color-warning))' : 'inherit' }}>{compareResult.file2.size_bytes.toLocaleString()} bytes</td>
                                            </tr>
                                            <tr>
                                                <td style={{ fontWeight: 600 }}>SHA-256</td>
                                                <td style={{ fontFamily: 'monospace', fontSize: '0.68rem', wordBreak: 'break-all', color: 'hsl(var(--color-primary))' }}>{compareResult.file1.sha256}</td>
                                                <td style={{ fontFamily: 'monospace', fontSize: '0.68rem', wordBreak: 'break-all', color: compareResult.hashes_match ? 'hsl(var(--color-success))' : 'hsl(var(--color-error))' }}>{compareResult.file2.sha256}</td>
                                            </tr>
                                            <tr>
                                                <td style={{ fontWeight: 600 }}>MD5</td>
                                                <td style={{ fontFamily: 'monospace', fontSize: '0.72rem', wordBreak: 'break-all', color: 'hsl(var(--text-secondary))' }}>{compareResult.file1.md5}</td>
                                                <td style={{ fontFamily: 'monospace', fontSize: '0.72rem', wordBreak: 'break-all', color: 'hsl(var(--text-secondary))' }}>{compareResult.file2.md5}</td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </Card>
                        </div>
                    )}
                </>
            )}
            

        </div>
    );
};
