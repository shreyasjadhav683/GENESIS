import type { ExportData } from './pdfExport';

// Interfaces needed for the report
interface RiskFactor {
    permission: string;
    risk: string;
    description: string;
}

interface Remediation {
    action: 'REMOVE' | 'REVIEW' | 'KEEP';
    description: string;
    steps: string[];
}

interface Extension {
    id: string;
    name: string;
    version: string;
    description: string;
    browser: string;
    manifest_version: number;
    permissions: string[];
    host_permissions: string[];
    risk_level: string;
    risk_score: number;
    risk_factors: RiskFactor[];
    author?: string;
    homepage_url?: string;
    remediation?: Remediation;
}

interface ScanResult {
    extensions: Extension[];
    summary: {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        browsers_scanned: string[];
    };
    scan_time: string;
}

export const generateExtensionScanReport = (result: ScanResult): ExportData => {
    const tables: Array<{ title: string; headers: string[]; rows: (string | number)[][] }> = [];
    
    // 1. Executive Summary Table
    tables.push({
        title: 'Executive Summary',
        headers: ['Metric', 'Count'],
        rows: [
            ['Total Extensions Scanned', result.summary.total],
            ['Critical Risk Extensions', result.summary.critical],
            ['High Risk Extensions', result.summary.high],
            ['Medium Risk Extensions', result.summary.medium],
            ['Low Risk Extensions', result.summary.low],
            ['Browsers Scanned', result.summary.browsers_scanned.join(', ')]
        ]
    });

    // 2. High Risk Extensions Detail
    const riskyExts = result.extensions.filter(e => e.risk_level === 'CRITICAL' || e.risk_level === 'HIGH');
    if (riskyExts.length > 0) {
        tables.push({
            title: 'CRITICAL & HIGH Risk Extensions - Immediate Action Required',
            headers: ['Extension', 'Risk Level', 'Action', 'Reason'],
            rows: riskyExts.map(ext => [
                `${ext.name} (${ext.browser})`,
                ext.risk_level,
                ext.remediation?.action || 'REMOVE',
                ext.remediation?.description || 'High security risk detected'
            ])
        });
    }

    // 3. All Extensions Overview
    if (result.extensions.length > 0) {
        tables.push({
            title: 'All Detected Extensions',
            headers: ['Browser', 'Name', 'Version', 'Risk Level', 'Score'],
            rows: result.extensions.map(ext => [
                ext.browser,
                ext.name,
                ext.version,
                ext.risk_level,
                ext.risk_score
            ])
        });
    }
    
    // 4. Detailed Remediation Steps
    if (riskyExts.length > 0) {
            tables.push({
            title: 'Remediation Instructions',
            headers: ['Extension', 'Step-by-Step Removal Guide'],
            rows: riskyExts.map(ext => [
                ext.name,
                (ext.remediation?.steps || []).join('\n')
            ])
        });
    }

    // 5. Medium & Low Risk Actions
    const otherExts = result.extensions.filter(e => e.risk_level === 'MEDIUM' || e.risk_level === 'LOW');
    if (otherExts.length > 0) {
        tables.push({
            title: 'Recommended Actions for Medium & Low Risk Extensions',
            headers: ['Extension', 'Risk', 'Action', 'Steps/Notes'],
            rows: otherExts.map(ext => [
                ext.name,
                ext.risk_level,
                ext.remediation?.action || 'REVIEW',
                (ext.remediation?.steps && ext.remediation.steps.length > 0) 
                    ? ext.remediation.steps.join('\n') 
                    : ext.remediation?.description || 'No specific steps provided.'
            ])
        });
    }
    
    return {
        title: 'Browser Extension Security Risk Assessment',
        subtitle: `Comprehensive Analysis of ${result.summary.total} Extensions`,
        summary: {
            'Scan Date': new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
            'Risk Status': result.summary.critical > 0 ? 'CRITICAL' : result.summary.high > 0 ? 'HIGH' : 'SAFE',
            'Browsers': result.summary.browsers_scanned.join(', '),
            'Total Extensions': result.summary.total,
            'Critical Risks': result.summary.critical,
            'High Risks': result.summary.high
        },
        tables,
        flags: result.extensions
            .filter(e => e.risk_level === 'CRITICAL' || e.risk_level === 'HIGH')
            .map(e => `CRITICAL: ${e.name} has dangerous permissions: ${e.risk_factors.map(r => r.permission).join(', ')}`)
    };
};
