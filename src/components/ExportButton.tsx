import { Download, FileText, FileJson } from 'lucide-react';
import { useState } from 'react';
import type { ExportData } from '../utils/pdfExport';
import { exportToPDF, exportToJSON } from '../utils/pdfExport';

interface ExportButtonProps {
    getPDFData: () => ExportData;
    getJSONData?: () => any;
    disabled?: boolean;
}

export const ExportButton = ({ getPDFData, getJSONData, disabled }: ExportButtonProps) => {
    const [showMenu, setShowMenu] = useState(false);

    const handleExportPDF = () => {
        exportToPDF(getPDFData());
        setShowMenu(false);
    };

    const handleExportJSON = () => {
        if (getJSONData) {
            const data = getJSONData();
            exportToJSON(data, getPDFData().title);
        }
        setShowMenu(false);
    };

    return (
        <div style={{ position: 'relative', display: 'inline-block' }}>
            <button
                onClick={() => setShowMenu(!showMenu)}
                disabled={disabled}
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    padding: '0.5rem 1rem',
                    borderRadius: 'var(--radius-md)',
                    border: '1px solid hsl(var(--border-color))',
                    background: 'hsl(var(--bg-secondary))',
                    color: disabled ? 'hsl(var(--text-muted))' : 'hsl(var(--text-primary))',
                    cursor: disabled ? 'not-allowed' : 'pointer',
                    fontWeight: 600,
                    fontSize: '0.875rem',
                    transition: 'all 0.2s ease'
                }}
            >
                <Download size={16} />
                Export
            </button>

            {showMenu && !disabled && (
                <>
                    <div 
                        style={{
                            position: 'fixed',
                            inset: 0,
                            zIndex: 99
                        }}
                        onClick={() => setShowMenu(false)}
                    />
                    <div style={{
                        position: 'absolute',
                        top: '100%',
                        right: 0,
                        marginTop: '0.5rem',
                        background: 'hsl(var(--bg-card))',
                        border: '1px solid hsl(var(--border-color))',
                        borderRadius: 'var(--radius-lg)',
                        boxShadow: '0 10px 25px rgba(0,0,0,0.3)',
                        zIndex: 100,
                        minWidth: '180px',
                        overflow: 'hidden'
                    }}>
                        <button
                            onClick={handleExportPDF}
                            style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.75rem',
                                width: '100%',
                                padding: '0.75rem 1rem',
                                border: 'none',
                                background: 'transparent',
                                color: 'hsl(var(--text-primary))',
                                cursor: 'pointer',
                                textAlign: 'left',
                                fontSize: '0.875rem'
                            }}
                            onMouseEnter={(e) => e.currentTarget.style.background = 'hsl(var(--bg-hover))'}
                            onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                        >
                            <FileText size={18} style={{ color: 'hsl(var(--color-error))' }} />
                            Export as PDF
                        </button>
                        {getJSONData && (
                            <button
                                onClick={handleExportJSON}
                                style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '0.75rem',
                                    width: '100%',
                                    padding: '0.75rem 1rem',
                                    border: 'none',
                                    background: 'transparent',
                                    color: 'hsl(var(--text-primary))',
                                    cursor: 'pointer',
                                    textAlign: 'left',
                                    fontSize: '0.875rem'
                                }}
                                onMouseEnter={(e) => e.currentTarget.style.background = 'hsl(var(--bg-hover))'}
                                onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                            >
                                <FileJson size={18} style={{ color: 'hsl(var(--color-info))' }} />
                                Export as JSON
                            </button>
                        )}
                    </div>
                </>
            )}
        </div>
    );
};
