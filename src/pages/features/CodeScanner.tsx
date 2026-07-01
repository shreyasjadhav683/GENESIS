
import React, { useState, useRef } from 'react';
import { Card } from '../../components/Card';
import { Button } from '../../components/Button';
import {
    Bug, AlertTriangle, Code, Zap, RefreshCw, Upload, FileCode, ChevronDown, History as HistoryIcon
} from 'lucide-react';
import { api } from '../../services/api';
import { ScanHistoryTable } from '../../components/ScanHistoryTable';
import { ExportButton } from '../../components/ExportButton';
import { ScanResultViewer } from '../../components/ScanResultViewer';

const LANGUAGES = [
    { value: 'auto', label: 'Auto-Detect' },
    { value: 'python', label: 'Python' },
    { value: 'javascript', label: 'JavaScript' },
    { value: 'typescript', label: 'TypeScript' },
    { value: 'java', label: 'Java' },
    { value: 'c', label: 'C' },
    { value: 'cpp', label: 'C++' },
    { value: 'php', label: 'PHP' },
    { value: 'go', label: 'Go' },
    { value: 'ruby', label: 'Ruby' },
];



export const CodeScanner = () => {
    const [code, setCode] = useState('');
    const [language, setLanguage] = useState('auto');
    const [inputMode, setInputMode] = useState<'paste' | 'file'>('paste');
    const [selectedFile, setSelectedFile] = useState<File | null>(null);
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<any>(null);
    const [error, setError] = useState<string | null>(null);
    const [showInput, setShowInput] = useState(true);
    const [showHistory, setShowHistory] = useState(false);
    const fileInputRef = useRef<HTMLInputElement>(null);

    const handleScan = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(null);
        setResult(null);


        try {
            let response;

            if (inputMode === 'file' && selectedFile) {
                const formData = new FormData();
                formData.append('file', selectedFile);
                response = await api.post('/scan/code', formData, {
                    headers: { 'Content-Type': 'multipart/form-data' }
                });
            } else if (inputMode === 'paste' && code.trim()) {
                response = await api.post('/scan/code', {
                    code: code.trim(),
                    language: language === 'auto' ? '' : language,
                    filename: 'snippet'
                });
            } else {
                setError('Please provide code to analyze');
                setLoading(false);
                return;
            }

            if (response.data.error) {
                setError(response.data.error);
            } else {
                setResult(response.data);
                setShowInput(false);
            }
        } catch (err: any) {
            setError(err.response?.data?.detail || err.message || 'Failed to analyze code');
        } finally {
            setLoading(false);
        }
    };

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files?.[0]) {
            setSelectedFile(e.target.files[0]);
        }
    };



    const handleNewScan = () => {
        setResult(null);
        setCode('');
        setSelectedFile(null);
        setShowInput(true);

    };



    return (
        <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
            {/* Page Header */}
            <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div className="page-header-icon" style={{ background: 'hsla(30, 100%, 50%, 0.1)', color: '#f97316' }}>
                        <Bug size={28} />
                    </div>
                    <div>
                        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Code Scanner</h1>
                        <p style={{ color: 'hsl(var(--text-secondary))', margin: 0, fontSize: '0.9rem' }}>Aggressive multi-language SAST with 100+ vulnerability checks</p>
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
                                    <ScanHistoryTable type="CODE" onDelete={() => {}} />
                                </div>
                            </div>
                        </>
                    )}
                </div>
            </div>

            {/* Input Section — collapsible after scan */}
            {showInput && (
                <Card title="Source Code" style={{ marginBottom: '1.5rem' }}>
                    <form onSubmit={handleScan} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                        {/* Mode Toggle + Language Selector */}
                        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                            <div style={{
                                display: 'flex', borderRadius: 'var(--radius-md)', overflow: 'hidden',
                                border: '1px solid hsl(var(--border-color))'
                            }}>
                                <button type="button" onClick={() => setInputMode('paste')} style={{
                                    padding: '0.35rem 0.75rem', fontSize: '0.72rem', fontWeight: 600,
                                    border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.3rem',
                                    background: inputMode === 'paste' ? 'hsl(var(--color-primary))' : 'hsl(var(--bg-secondary))',
                                    color: inputMode === 'paste' ? 'white' : 'hsl(var(--text-secondary))',
                                }}>
                                    <Code size={13} /> Paste
                                </button>
                                <button type="button" onClick={() => setInputMode('file')} style={{
                                    padding: '0.35rem 0.75rem', fontSize: '0.72rem', fontWeight: 600,
                                    border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.3rem',
                                    background: inputMode === 'file' ? 'hsl(var(--color-primary))' : 'hsl(var(--bg-secondary))',
                                    color: inputMode === 'file' ? 'white' : 'hsl(var(--text-secondary))',
                                }}>
                                    <Upload size={13} /> File
                                </button>
                            </div>

                            <div style={{ flex: 1 }} />

                            <div style={{ position: 'relative' }}>
                                <select
                                    value={language}
                                    onChange={(e) => setLanguage(e.target.value)}
                                    style={{
                                        padding: '0.35rem 1.5rem 0.35rem 0.5rem', fontSize: '0.72rem', fontWeight: 600,
                                        border: '1px solid hsl(var(--border-color))', borderRadius: 'var(--radius-md)',
                                        background: 'hsl(var(--bg-secondary))', color: 'hsl(var(--text-primary))',
                                        appearance: 'none', cursor: 'pointer'
                                    }}
                                >
                                    {LANGUAGES.map(l => <option key={l.value} value={l.value}>{l.label}</option>)}
                                </select>
                                <ChevronDown size={12} style={{
                                    position: 'absolute', right: '0.4rem', top: '50%', transform: 'translateY(-50%)',
                                    color: 'hsl(var(--text-muted))', pointerEvents: 'none'
                                }} />
                            </div>
                        </div>

                        {/* Input Area */}
                        {inputMode === 'paste' ? (
                            <textarea
                                className="input-field"
                                style={{
                                    minHeight: '250px', maxHeight: '400px', resize: 'vertical', fontFamily: 'monospace',
                                    fontSize: '0.82rem', lineHeight: 1.6
                                }}
                                placeholder="Paste your code here for aggressive security analysis..."
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                spellCheck={false}
                            />
                        ) : (
                            <div
                                onClick={() => fileInputRef.current?.click()}
                                style={{
                                    minHeight: '100px', display: 'flex', flexDirection: 'column',
                                    alignItems: 'center', justifyContent: 'center', gap: '0.75rem',
                                    border: '2px dashed hsl(var(--border-color))',
                                    borderRadius: 'var(--radius-md)', cursor: 'pointer',
                                    background: selectedFile ? 'hsla(var(--color-success), 0.04)' : 'hsl(var(--bg-secondary))',
                                    transition: 'all 0.2s'
                                }}
                            >
                                <input ref={fileInputRef} type="file" accept=".py,.js,.ts,.tsx,.jsx,.java,.c,.cpp,.h,.hpp,.php,.go,.rb,.rs" onChange={handleFileChange} hidden />
                                {selectedFile ? (
                                    <>
                                        <FileCode size={36} style={{ color: 'hsl(var(--color-success))' }} />
                                        <p style={{ fontWeight: 700, fontSize: '0.85rem' }}>{selectedFile.name}</p>
                                        <p style={{ fontSize: '0.72rem', color: 'hsl(var(--text-muted))' }}>
                                            {(selectedFile.size / 1024).toFixed(1)} KB — Click to change
                                        </p>
                                    </>
                                ) : (
                                    <>
                                        <Upload size={36} style={{ color: 'hsl(var(--text-muted))', opacity: 0.4 }} />
                                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.82rem' }}>Click to select a source file</p>
                                        <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.65rem' }}>.py .js .ts .java .c .cpp .php .go .rb</p>
                                    </>
                                )}
                            </div>
                        )}

                        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                            <Button type="submit" isLoading={loading} variant="primary">
                                <Zap size={18} />
                                {loading ? 'Scanning...' : 'Deep Analyze'}
                            </Button>
                        </div>

                        {loading && (
                            <div>
                                <p style={{ fontSize: '0.7rem', color: 'hsl(var(--text-muted))', marginBottom: '0.35rem' }}>
                                    Running multi-language SAST (patterns, AST, entropy, metrics)...
                                </p>
                                <div style={{ height: '3px', borderRadius: '2px', background: 'hsl(var(--bg-secondary))', overflow: 'hidden' }}>
                                    <div style={{
                                        height: '100%', width: '60%', borderRadius: '2px',
                                        background: 'linear-gradient(90deg, hsl(var(--color-primary)), hsl(var(--color-secondary)))',
                                        animation: 'shimmer 1.5s infinite'
                                    }} />
                                </div>
                            </div>
                        )}
                    </form>
                </Card>
            )}

            {/* Error */}
            {error && (
                <div style={{
                    padding: '1rem', marginBottom: '1.5rem',
                    background: 'hsl(var(--color-error-light))',
                    border: '1px solid hsla(var(--color-error), 0.3)',
                    borderRadius: 'var(--radius-lg)', color: 'hsl(var(--color-error))',
                    fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.75rem'
                }}>
                    <AlertTriangle size={20} /> {error}
                </div>
            )}

            {/* Results — full width */}
            {result && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                    {/* Top Bar: Actions */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <button
                            onClick={() => setShowInput(!showInput)}
                            style={{
                                display: 'flex', alignItems: 'center', gap: '0.4rem',
                                padding: '0.35rem 0.75rem', border: '1px solid hsl(var(--border-color))',
                                borderRadius: 'var(--radius-md)', background: 'hsl(var(--bg-secondary))',
                                color: 'hsl(var(--text-secondary))', cursor: 'pointer',
                                fontSize: '0.72rem', fontWeight: 600
                            }}
                        >
                            <Code size={14} />
                            {showInput ? 'Hide Code' : 'Show Code'}
                            <ChevronDown size={12} style={{ transform: showInput ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }} />
                        </button>
                        <div style={{ display: 'flex', gap: '0.5rem' }}>
                            <ExportButton
                                getPDFData={() => ({
                                    title: 'Code Security Analysis Report',
                                    subtitle: `${result.language?.toUpperCase()} — ${result.filename}`,
                                    summary: {
                                        'Target': result.filename, 'Language': result.language,
                                        'Lines': result.lines_analyzed, 'Grade': result.grade,
                                        'Risk Score': `${result.risk_score}/100`, 'Risk Level': result.risk_level,
                                        'Date': new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
                                        'Critical': result.summary?.critical || 0, 'High': result.summary?.high || 0,
                                        'Medium': result.summary?.medium || 0, 'Low': result.summary?.low || 0,
                                    },
                                    tables: result.vulnerabilities?.length > 0 ? [{
                                        title: 'Vulnerabilities', headers: ['Line', 'Severity', 'Type', 'Category', 'CWE', 'Description'],
                                        rows: result.vulnerabilities.map((v: any) => [v.line || '-', v.severity, v.type, v.category || '', v.cwe_id || '', v.description])
                                    }] : [],
                                    flags: result.vulnerabilities?.filter((v: any) => v.severity === 'CRITICAL' || v.severity === 'HIGH')
                                        .map((v: any) => `Line ${v.line}: ${v.type} — ${v.description}`)
                                })}
                                getJSONData={() => result}
                            />
                            <Button onClick={handleNewScan} variant="primary" size="sm">
                                <RefreshCw size={16} /> New Scan
                            </Button>
                        </div>
                    </div>

                    <ScanResultViewer 
                        scanType="CODE_SCAN" 
                        target={result.filename || 'Snippet'} 
                        result={result} 
                        createdAt={new Date().toISOString()} 
                    />
                </div>
            )}


        </div>
    );
};
