
import React, { useState } from 'react';
import { Card } from '../../components/Card';
import { FileUpload } from '../../components/FileUpload';
import { Button } from '../../components/Button';
import { FileCode, RefreshCw, FileSearch, History, AlertTriangle } from 'lucide-react';
import { ScanHistoryTable } from '../../components/ScanHistoryTable';
import { ScanResultViewer } from '../../components/ScanResultViewer';
import { ExportButton } from '../../components/ExportButton';



const privacyChecks = (result: any) => {
    const checks: Array<{ label: string; found: boolean; severity: string; detail: string }> = [];
    
    if (result.gps && Object.keys(result.gps).length > 0) {
        checks.push({ label: 'GPS Location Data', found: true, severity: 'HIGH', detail: 'File contains GPS coordinates that reveal where it was created' });
    }
    if (result.exif) {
        const exifKeys = Object.keys(result.exif).map(k => k.toLowerCase());
        if (exifKeys.some(k => k.includes('make') || k.includes('model'))) {
            checks.push({ label: 'Camera/Device Info', found: true, severity: 'MEDIUM', detail: 'Device make and model are embedded in the file' });
        }
        if (exifKeys.some(k => k.includes('software'))) {
            checks.push({ label: 'Software Info', found: true, severity: 'LOW', detail: 'Editing software information is stored in metadata' });
        }
    }
    if (result.extended_metadata) {
        const extKeys = Object.keys(result.extended_metadata).map(k => k.toLowerCase());
        if (extKeys.some(k => k.includes('author') || k.includes('creator') || k.includes('last_modified_by'))) {
            checks.push({ label: 'Author Identity', found: true, severity: 'MEDIUM', detail: 'Author name or user identity is embedded' });
        }
    }
    
    if (checks.length === 0) {
        checks.push({ label: 'No Privacy Risks', found: false, severity: 'SAFE', detail: 'No sensitive metadata detected' });
    }
    
    return checks;
};



export const MetadataViewer = () => {
    const [file, setFile] = useState<File | null>(null);
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<any>(null);
    const [error, setError] = useState<string | null>(null);
    const [showHistory, setShowHistory] = useState(false);

    const handleScan = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!file) { setError("Please upload an image or document"); return; }

        setLoading(true);
        setError(null);
        setResult(null);

        try {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('last_modified', file.lastModified.toString());

            const token = localStorage.getItem('token');
            const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
            const response = await fetch(`${apiBase}/files/metadata`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` },
                body: formData
            });

            if (!response.ok) throw new Error('Failed to extract metadata');
            setResult(await response.json());
        } catch (err: any) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const formatBytes = (bytes: number): string => {
        if (!bytes) return 'N/A';
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    };



    const privacy = result ? privacyChecks(result) : [];

    return (
        <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
            {/* Page Header */}
            <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div className="page-header-icon" style={{ background: 'hsla(45, 100%, 50%, 0.1)', color: '#eab308' }}>
                        <FileCode size={28} />
                    </div>
                    <div>
                        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Metadata Viewer</h1>
                        <p style={{ color: 'hsl(var(--text-secondary))', margin: 0, fontSize: '0.9rem' }}>Extract hidden EXIF, GPS, and document metadata from files</p>
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
                                    <ScanHistoryTable type="METADATA" onDelete={() => {}} />
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
                        label="Upload File" 
                        accept="*"
                        currentFile={file} 
                        onFileSelect={setFile} 
                    />
                    <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                        <Button type="submit" isLoading={loading} disabled={!file} variant="primary">
                            <FileSearch size={18} />
                            Extract Metadata
                        </Button>
                    </div>
                </form>
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

            {/* Results */}
            {result && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    {/* Actions Bar */}
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                        <ExportButton 
                            getPDFData={() => {
                                const tables: Array<{ title: string; headers: string[]; rows: (string | number)[][] }> = [];
                                tables.push({
                                    title: 'File Information',
                                    headers: ['Property', 'Value'],
                                    rows: [
                                        ['Filename', result.filename || 'N/A'],
                                        ['Content Type', result.content_type || 'N/A'],
                                        ['File Size', formatBytes(result.size_bytes)],
                                        ['Created', result.created_at || 'N/A'],
                                        ['Modified', result.modified_at || 'N/A'],
                                        ...(result.is_image ? [
                                            ['Format', result.format || 'N/A'],
                                            ['Dimensions', `${result.dimensions?.[0]} × ${result.dimensions?.[1]} px`]
                                        ] : [])
                                    ]
                                });
                                if (result.extended_metadata && Object.keys(result.extended_metadata).length > 0) {
                                    tables.push({
                                        title: 'Extended Metadata',
                                        headers: ['Property', 'Value'],
                                        rows: Object.entries(result.extended_metadata)
                                            .filter(([_, v]) => v !== null && v !== 'None' && v !== '')
                                            .map(([k, v]) => [k, String(v)])
                                    });
                                }
                                return {
                                    title: 'Metadata Analysis Report',
                                    subtitle: result.filename,
                                    summary: {
                                        'Target': result.filename,
                                        'Scan Type': 'Metadata Analysis',
                                        'Date': new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
                                        'Content Type': result.content_type,
                                        'File Size': formatBytes(result.size_bytes),
                                    },
                                    tables,
                                    flags: privacy.filter(p => p.found).map(p => `${p.label}: ${p.detail}`)
                                };
                            }}
                            getJSONData={() => result}
                        />
                        <Button onClick={() => { setFile(null); setResult(null); }} variant="secondary" size="sm">
                            <RefreshCw size={16} />
                            Scan Another
                        </Button>
                    </div>

                    <ScanResultViewer 
                        scanType="METADATA" 
                        target={result.filename || 'Unknown File'} 
                        result={result} 
                        createdAt={new Date().toISOString()}
                    />
                </div>
            )}


        </div>
    );
};
