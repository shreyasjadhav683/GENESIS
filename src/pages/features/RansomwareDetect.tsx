
import React, { useState } from 'react';
import { Card } from '../../components/Card';
import { FileUpload } from '../../components/FileUpload';
import { Button } from '../../components/Button';
import { ShieldAlert, AlertTriangle, ShieldCheck, Zap, RefreshCw, History as HistoryIcon } from 'lucide-react';
import { ScanHistoryTable } from '../../components/ScanHistoryTable';
import { ExportButton } from '../../components/ExportButton';
import { ScanResultViewer } from '../../components/ScanResultViewer';

const formatBytes = (bytes: number): string => {
    if (!bytes) return 'N/A';
    if (bytes < 1024) return bytes + ' bytes';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
};



export const RansomwareDetect = () => {
    const [file, setFile] = useState<File | null>(null);
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<any>(null);
    const [error, setError] = useState<string | null>(null);
    const [showHistory, setShowHistory] = useState(false);

    const handleScan = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!file) {
            setError("Please upload a file to analyze");
            return;
        }

        setLoading(true);
        setError(null);
        setResult(null);

        try {
            const formData = new FormData();
            formData.append('file', file);

            const token = localStorage.getItem('token');
            const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
            const response = await fetch(`${apiBase}/scan/ransomware`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` },
                body: formData
            });

            if (!response.ok) throw new Error('Analysis failed');
            const data = await response.json();
            setResult(data);
        } catch (err: any) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };



    return (
        <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
            {/* Page Header */}
            <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div className="page-header-icon" style={{ background: 'hsla(var(--color-error), 0.1)', color: 'hsl(var(--color-error))' }}>
                        <ShieldAlert size={28} />
                    </div>
                    <div>
                        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Ransomware Detector</h1>
                        <p style={{ color: 'hsl(var(--text-secondary))', margin: 0, fontSize: '0.9rem' }}>Heuristic analysis for ransomware signatures &amp; encrypted payloads</p>
                    </div>
                </div>
                <div style={{ position: 'relative' }}>
                    <Button 
                        variant="secondary" 
                        onClick={() => setShowHistory(!showHistory)}
                        style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                    >
                        <HistoryIcon size={18} />
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
                                    <ScanHistoryTable type="RANSOMWARE" onDelete={() => {}} />
                                </div>
                            </div>
                        </>
                    )}
                </div>
            </div>

            {/* Upload Card */}
            <Card style={{ marginBottom: '1.5rem' }}>
                <form onSubmit={handleScan} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    <FileUpload 
                        label="Upload Suspect File" 
                        currentFile={file} 
                        onFileSelect={setFile} 
                    />
                    <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                        <Button type="submit" isLoading={loading} disabled={!file} variant="danger">
                            <Zap size={18} />
                            Run Heuristic Analysis
                        </Button>
                    </div>
                </form>
            </Card>

            {/* Error */}
            {error && (
                <div style={{ 
                    padding: '1rem', 
                    background: 'hsl(var(--color-error-light))', 
                    border: '1px solid hsla(var(--color-error), 0.3)', 
                    borderRadius: 'var(--radius-lg)', 
                    color: 'hsl(var(--color-error))', 
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.75rem',
                    marginBottom: '1.5rem'
                }}>
                    <AlertTriangle size={20} />
                    {error}
                </div>
            )}

            {/* Results */}
            {result && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                    {/* Actions Bar */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                            {result.ransomware_detected ? 
                                <ShieldAlert size={24} style={{ color: 'hsl(var(--color-error))' }} /> :
                                <ShieldCheck size={24} style={{ color: 'hsl(var(--color-success))' }} />
                            }
                            <span style={{ 
                                fontWeight: 700, 
                                color: result.ransomware_detected ? 'hsl(var(--color-error))' : 'hsl(var(--color-success))'
                            }}>
                                {result.ransomware_detected ? 'Ransomware Detected' : 'File Appears Clean'}
                            </span>
                        </div>
                        <div style={{ display: 'flex', gap: '0.5rem' }}>
                            <ExportButton 
                                getPDFData={() => ({
                                    title: 'Ransomware Analysis Report',
                                    subtitle: file?.name || 'File Analysis',
                                    summary: {
                                        'Target': file?.name || 'Unknown File',
                                        'Scan Type': 'Ransomware Detection',
                                        'Date': new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
                                        'Verdict': result.ransomware_detected ? 'THREAT DETECTED' : 'CLEAN',
                                        'File Entropy': result.entropy?.toFixed(4) || 'N/A',
                                        'File Type': file?.type || 'Unknown',
                                        'File Size': formatBytes(file?.size || 0),
                                    },
                                    tables: [{
                                        title: 'Analysis Details',
                                        headers: ['Metric', 'Value'],
                                        rows: [
                                            ['File Name', file?.name || 'N/A'],
                                            ['File Size', formatBytes(file?.size || 0)],
                                            ['File Type', file?.type || 'Unknown'],
                                            ['Entropy', result.entropy?.toFixed(4) || 'N/A'],
                                            ['Detection', result.ransomware_detected ? 'MALICIOUS' : 'CLEAN'],
                                        ]
                                    }],
                                    flags: result.ransomware_detected ? [result.details || 'Ransomware signatures detected'] : []
                                })}
                                getJSONData={() => result}
                            />
                            <Button onClick={() => { setResult(null); setFile(null); }} variant="secondary" size="sm">
                                <RefreshCw size={16} />
                                New Scan
                            </Button>
                        </div>
                    </div>

                    <ScanResultViewer 
                        scanType="RANSOMWARE_SCAN" 
                        target={file?.name || 'File'} 
                        result={{
                            ...result,
                            filename: file?.name,
                            filesize: file?.size,
                            filetype: file?.type
                        }} 
                        createdAt={new Date().toISOString()} 
                    />
                </div>
            )}


        </div>
    );
};
