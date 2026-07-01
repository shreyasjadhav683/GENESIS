
import { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { api } from '../services/api';
import { Trash2, History, Clock, RefreshCw, Eye, Download, X } from 'lucide-react';
import { Card } from './Card';
import { exportToPDF } from '../utils/pdfExport';
import { ScanResultViewer } from './ScanResultViewer';
import { generateExtensionScanReport } from '../utils/reportGenerators';

interface HistoryItem {
    id: number;
    scan_type: string;
    target: string;
    result: string;
    created_at: string;
}

interface ScanHistoryTableProps {
    type?: 'IP' | 'URL' | 'FILE' | 'METADATA' | 'SECURITY_HEADERS' | 'PHISHING' | 'EMAIL' | 'PASSWORD' | 'CODE' | 'RANSOMWARE' | 'BROWSER_EXTENSIONS' | 'WHOIS_DNS' | 'SSL';
    onDelete?: () => void;
    alwaysOpen?: boolean;
}

const getScanTypeName = (scanType: string): string => {
    const typeMap: Record<string, string> = {
        'URL_AGGRESSIVE_SCAN': 'URL Scan',
        'IP_COMPREHENSIVE_SCAN': 'IP Scan',
        'IP_CHECK': 'IP Check',
        'FILE_INTEGRITY': 'File Integrity',
        'FILE_COMPARE': 'File Compare',
        'METADATA_SCAN': 'Metadata',
        'EMAIL_HEADERS': 'Email Headers',
        'SECURITY_HEADERS': 'Security Headers',
        'PHISHING_CHECK': 'Phishing Check',
        'PASSWORD_STRENGTH': 'Password Strength',
        'CODE_SCAN': 'Code Scan',
        'RANSOMWARE_SCAN': 'Ransomware Scan',
        'BROWSER_EXTENSIONS': 'Extension Scan',
        'WHOIS_LOOKUP': 'WHOIS Lookup',
        'DNS_LOOKUP': 'DNS Lookup',
        'SSL_CHECK': 'SSL Check',
    };
    return typeMap[scanType] || scanType.replace(/_/g, ' ');
};

const getScanTypeColor = (scanType: string): { bg: string; text: string; border: string } => {
    const colorMap: Record<string, { bg: string; text: string; border: string }> = {
        'URL_AGGRESSIVE_SCAN': { bg: 'hsl(var(--color-secondary-light))', text: 'hsl(var(--color-secondary))', border: 'hsla(var(--color-secondary), 0.3)' },
        'IP_COMPREHENSIVE_SCAN': { bg: 'hsl(var(--color-primary-light))', text: 'hsl(var(--color-primary))', border: 'hsla(var(--color-primary), 0.3)' },
        'IP_CHECK': { bg: 'hsl(var(--color-primary-light))', text: 'hsl(var(--color-primary))', border: 'hsla(var(--color-primary), 0.3)' },
        'FILE_INTEGRITY': { bg: 'hsl(var(--color-success-light))', text: 'hsl(var(--color-success))', border: 'hsla(var(--color-success), 0.3)' },
        'FILE_COMPARE': { bg: 'hsla(var(--color-info), 0.1)', text: 'hsl(var(--color-info))', border: 'hsla(var(--color-info), 0.3)' },
        'METADATA_SCAN': { bg: 'hsl(var(--color-info-light))', text: 'hsl(var(--color-info))', border: 'hsla(var(--color-info), 0.3)' },
        'EMAIL_HEADERS': { bg: 'hsl(var(--color-warning-light))', text: 'hsl(var(--color-warning))', border: 'hsla(var(--color-warning), 0.3)' },
        'SECURITY_HEADERS': { bg: 'hsl(var(--color-success-light))', text: 'hsl(var(--color-success))', border: 'hsla(var(--color-success), 0.3)' },
        'PHISHING_CHECK': { bg: 'hsl(var(--color-error-light))', text: 'hsl(var(--color-error))', border: 'hsla(var(--color-error), 0.3)' },
        'PASSWORD_STRENGTH': { bg: 'hsl(var(--color-secondary-light))', text: 'hsl(var(--color-secondary))', border: 'hsla(var(--color-secondary), 0.3)' },
        'CODE_SCAN': { bg: 'hsl(var(--color-info-light))', text: 'hsl(var(--color-info))', border: 'hsla(var(--color-info), 0.3)' },
        'RANSOMWARE_SCAN': { bg: 'hsl(var(--color-error-light))', text: 'hsl(var(--color-error))', border: 'hsla(var(--color-error), 0.3)' },
        'BROWSER_EXTENSIONS': { bg: 'hsla(270, 100%, 60%, 0.1)', text: '#a855f7', border: 'hsla(270, 100%, 60%, 0.3)' },
        'WHOIS_LOOKUP': { bg: 'hsla(var(--color-info), 0.1)', text: 'hsl(var(--color-info))', border: 'hsla(var(--color-info), 0.3)' },
        'DNS_LOOKUP': { bg: 'hsla(var(--color-info), 0.1)', text: 'hsl(var(--color-info))', border: 'hsla(var(--color-info), 0.3)' },
        'SSL_CHECK': { bg: 'hsl(var(--color-success-light))', text: 'hsl(var(--color-success))', border: 'hsla(var(--color-success), 0.3)' },
    };
    return colorMap[scanType] || { bg: 'hsl(var(--bg-tertiary))', text: 'hsl(var(--text-secondary))', border: 'hsl(var(--border-color))' };
};

export const ScanHistoryTable = ({ type, onDelete, alwaysOpen = false }: ScanHistoryTableProps) => {
    const [history, setHistory] = useState<HistoryItem[]>([]);
    const [loading, setLoading] = useState(false);
    const [isOpen, setIsOpen] = useState(alwaysOpen);
    const [selectedItem, setSelectedItem] = useState<HistoryItem | null>(null);

    const fetchHistory = async () => {
        setLoading(true);
        try {
            const response = await api.get('/history');
            let data: HistoryItem[] = response.data;
            
            if (type) {
                const typeFilters: Record<string, string[]> = {
                    'IP': ['IP_COMPREHENSIVE_SCAN', 'IP_CHECK'],
                    'URL': ['URL_AGGRESSIVE_SCAN'],
                    'FILE': ['FILE_INTEGRITY', 'FILE_COMPARE'],
                    'METADATA': ['METADATA_SCAN'],
                    'SECURITY_HEADERS': ['SECURITY_HEADERS'],
                    'PHISHING': ['PHISHING_CHECK'],
                    'EMAIL': ['EMAIL_HEADERS'],
                    'PASSWORD': ['PASSWORD_STRENGTH'],
                    'CODE': ['CODE_SCAN'],
                    'RANSOMWARE': ['RANSOMWARE_SCAN'],
                    'BROWSER_EXTENSIONS': ['BROWSER_EXTENSIONS'],
                    'WHOIS_DNS': ['WHOIS_LOOKUP', 'DNS_LOOKUP'],
                    'SSL': ['SSL_CHECK'],
                };
                const allowedTypes = typeFilters[type] || [];
                if (allowedTypes.length > 0) {
                    data = data.filter(item => allowedTypes.includes(item.scan_type));
                }
            }
            
            setHistory(data);
        } catch (err) {
            console.error("Failed to fetch history:", err);
        } finally {
            setLoading(false);
        }
    };

    const handleToggle = () => {
        if (!isOpen && history.length === 0) {
            fetchHistory();
        }
        setIsOpen(!isOpen);
    };

    useEffect(() => {
        if (alwaysOpen || isOpen) {
            fetchHistory();
        }
    }, [type, alwaysOpen, isOpen]);

    const handleDelete = async (id: number) => {
        if (!confirm("Are you sure you want to delete this history record?")) return;
        try {
            await api.delete(`/history/${id}`);
            setHistory(prev => prev.filter(item => item.id !== id));
            if (onDelete) onDelete();
        } catch (err) {
            alert("Failed to delete history item");
        }
    };
    
    const handleDeleteAll = async () => {
        if (!confirm("Are you sure you want to delete ALL history for this category?")) return;
        try {
            if (!type) {
                await api.delete('/history');
                setHistory([]);
            } else {
                for (const item of history) {
                    await api.delete(`/history/${item.id}`);
                }
                setHistory([]);
            }
            if (onDelete) onDelete();
        } catch(err) {
            alert("Failed to clear history");
        }
    };

    const handleViewResult = (item: HistoryItem) => {
        setSelectedItem(item);
    };

    const handleExportItemPDF = (item: HistoryItem) => {
        try {
            const result = JSON.parse(item.result || '{}');
            const summary: Record<string, string | number> = {
                'Target': item.target,
                'Scan Type': getScanTypeName(item.scan_type),
                'Date': new Date(item.created_at).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
            };

            const tables: Array<{ title: string; headers: string[]; rows: string[][] }> = [];
            const flags: string[] = [];

            // Handle IP Scan results
            if (item.scan_type.includes('IP')) {
                const riskAssessment = result.risk_assessment || {};
                const threatIntel = result.threat_intelligence || {};
                const networkInfo = result.network_info || {};
                const geoDetails = result.geographic_details || {};
                const abuseHistory = result.abuse_history || {};
                const portScan = result.port_scan || {};
                const dnsInfo = result.dns_info || {};

                summary['Risk Score'] = `${riskAssessment.score || 0}/100`;
                summary['Severity'] = riskAssessment.severity || 'Unknown';
                summary['Verdict'] = riskAssessment.is_malicious ? 'MALICIOUS - BLOCK RECOMMENDED' : 'SAFE';
                summary['Recommendation'] = riskAssessment.recommendation || '';
                summary['Abuse Confidence'] = `${threatIntel.abuse_confidence_score || 0}%`;
                summary['Fraud Score'] = `${threatIntel.fraud_score || 0}%`;

                // Indicators
                const indicators: string[] = [];
                if (threatIntel.is_proxy) indicators.push('Proxy');
                if (threatIntel.is_tor_exit) indicators.push('Tor Exit');
                if (threatIntel.is_vpn) indicators.push('VPN');
                if (threatIntel.is_blacklisted) indicators.push('BLACKLISTED');
                if (threatIntel.is_datacenter) indicators.push('Datacenter');
                if (indicators.length > 0) summary['Indicators'] = indicators.join(', ');

                // Risk Factors table
                if (riskAssessment.factors && riskAssessment.factors.length > 0) {
                    tables.push({
                        title: 'Risk Factors',
                        headers: ['Factor', 'Impact', 'Description'],
                        rows: riskAssessment.factors.map((f: any) => [f.name, `+${f.impact}`, f.description])
                    });
                }

                // Network Details table
                tables.push({
                    title: 'Network Details',
                    headers: ['Property', 'Value'],
                    rows: [
                        ['IP Address', result.ip || item.target],
                        ['ISP', networkInfo.isp || 'N/A'],
                        ['Organization', networkInfo.organization || 'N/A'],
                        ['Domain', networkInfo.domain || 'N/A'],
                        ['ASN', networkInfo.asn || 'N/A'],
                        ['ASN Name', networkInfo.asn_name || 'N/A'],
                        ['Network Range', networkInfo.network_range || 'N/A'],
                        ['Reverse DNS', dnsInfo.reverse_dns || 'N/A'],
                    ]
                });

                // Location table
                tables.push({
                    title: 'Location & History',
                    headers: ['Property', 'Value'],
                    rows: [
                        ['Country', `${geoDetails.country || 'N/A'} ${geoDetails.country_code ? `(${geoDetails.country_code})` : ''}`],
                        ['Region', geoDetails.region_name || geoDetails.region || 'N/A'],
                        ['City', geoDetails.city || 'N/A'],
                        ['Timezone', geoDetails.timezone || 'N/A'],
                        ['Coordinates', geoDetails.latitude && geoDetails.longitude ? `${geoDetails.latitude}, ${geoDetails.longitude}` : 'N/A'],
                        ['Continent', geoDetails.continent || 'N/A'],
                        ['Total Reports', String(abuseHistory.total_reports || 0)],
                        ['Last Reported', abuseHistory.last_reported_at || threatIntel.last_reported || 'Never'],
                    ]
                });

                // Port Scan table
                if (portScan.open_ports && portScan.open_ports.length > 0) {
                    tables.push({
                        title: 'Port Scan Results',
                        headers: ['Port', 'Service', 'Status'],
                        rows: portScan.open_ports.map((port: number) => [
                            String(port),
                            portScan.services_detected?.[port] || 'Unknown',
                            'OPEN'
                        ])
                    });
                }
            } 
            // Handle URL Scan results
            else if (item.scan_type.includes('URL')) {
                const sha = result.security_headers_analysis;
                summary['Risk Score'] = `${result.risk_score || 0}/100`;
                summary['Risk Level'] = result.risk_level || 'Unknown';
                summary['Verdict'] = result.malicious ? 'MALICIOUS' : 'SAFE';
                summary['Domain'] = result.domain || '';
                summary['Final URL'] = result.final_url || '';
                summary['Status Code'] = result.status_code || '';
                summary['IP Address'] = result.ip_address || 'N/A';
                summary['Security Headers Grade'] = sha?.grade || 'N/A';
                summary['Domain Age'] = result.domain_info?.age_days != null ? `${result.domain_info.age_days} days` : 'N/A';

                if (result.redirect_chain?.length > 0) {
                    tables.push({
                        title: 'Redirect Chain',
                        headers: ['Step', 'Status', 'URL'],
                        rows: result.redirect_chain.map((r: any, idx: number) => [idx + 1, r.status, r.url])
                    });
                }
                if (sha?.headers?.length > 0) {
                    tables.push({
                        title: 'Security Headers',
                        headers: ['Status', 'Header', 'Value'],
                        rows: sha.headers.map((h: any) => [h.status.toUpperCase(), h.name, h.value || 'Not set'])
                    });
                }
                if (result.flags?.length > 0) {
                    tables.push({
                        title: 'Threat Flags',
                        headers: ['#', 'Flag'],
                        rows: result.flags.map((f: string, i: number) => [i + 1, f])
                    });
                    flags.push(...result.flags);
                }
            }
            // Handle File Integrity results
            else if (item.scan_type.includes('FILE_INTEGRITY') || item.scan_type.includes('INTEGRITY')) {
                const isClean = result.status === 'CLEAN' || result.hash_match === true;
                summary['Status'] = result.status || (isClean ? 'CLEAN' : 'MODIFIED');
                summary['Verdict'] = isClean ? 'File matches baseline' : 'File has been modified';
                summary['Details'] = result.details || '';

                const formatBytes = (bytes: number): string => {
                    if (!bytes) return 'N/A';
                    if (bytes < 1024) return bytes + ' bytes';
                    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
                    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
                };

                tables.push({
                    title: 'File Details',
                    headers: ['Property', 'Value'],
                    rows: [
                        ['Filename', result.filename || 'N/A'],
                        ['File Size', formatBytes(result.size_bytes)],
                        ['Current SHA-256', result.hash || result.current_hash || 'N/A'],
                        ['Current MD5', result.current_md5 || 'N/A'],
                        ['Baseline SHA-256', result.baseline_hash || 'N/A'],
                        ['Baseline Date', result.baseline_date ? new Date(result.baseline_date).toLocaleString() : 'N/A'],
                        ['Hash Match', isClean ? 'MATCH' : 'MISMATCH'],
                        ['Algorithm', result.algorithm || 'SHA-256'],
                    ]
                });
            }
            // Handle Browser Extensions results
            else if (item.scan_type === 'BROWSER_EXTENSIONS') {
                const reportData = generateExtensionScanReport(result);
                exportToPDF(reportData);
                return;
            }
            // Handle Security Headers results
            else if (item.scan_type === 'SECURITY_HEADERS') {
                summary['Security Grade'] = result.score >= 80 ? 'A' : result.score >= 60 ? 'C' : 'F';
                summary['Score'] = `${result.score}/100`;
                summary['Headers Present'] = result.present_count || 0;
                summary['Headers Missing'] = result.missing_count || 0;

                if (result.headers && result.headers.length > 0) {
                    tables.push({
                        title: 'Header Analysis',
                        headers: ['Status', 'Header Name', 'Value', 'Description'],
                        rows: result.headers.map((h: any) => [
                            h.status.toUpperCase(),
                            h.name,
                            h.value || 'Not set',
                            h.description
                        ])
                    });
                }
                const missingFlags = result.headers
                    ?.filter((h: any) => h.status === 'missing')
                    .map((h: any) => `Missing: ${h.name} - ${h.recommendation || h.description}`) || [];
                if (missingFlags.length > 0) flags.push(...missingFlags);
            }
            // Handle Phishing Check results
            else if (item.scan_type === 'PHISHING_CHECK') {
                summary['Verdict'] = result.verdict || '';
                summary['Risk Score'] = `${result.risk_score || 0}/100`;
                summary['Risk Level'] = result.risk_level || 'Unknown';
                summary['Final URL'] = result.final_url || '';
                summary['Domain'] = result.domain || '';
                summary['IP Address'] = result.ip_address || '';

                if (result.indicators?.length > 0) {
                    tables.push({
                        title: 'Phishing Indicators',
                        headers: ['Status', 'Indicator', 'Severity', 'Category', 'Description'],
                        rows: result.indicators.map((i: any) => [
                            i.detected ? 'DETECTED' : 'SAFE',
                            i.name, (i.severity || '').toUpperCase(), i.category || '', i.description
                        ])
                    });
                }
                if (result.flags?.length > 0) {
                    tables.push({
                        title: 'Critical Flags',
                        headers: ['Flag'],
                        rows: result.flags.map((f: string) => [f])
                    });
                }
                const detected = result.indicators?.filter((i: any) => i.detected) || [];
                if (detected.length > 0) flags.push(...detected.map((i: any) => `${i.name} - ${i.description}`));
            }
            // Handle Email Header Analysis results
            else if (item.scan_type === 'EMAIL_HEADERS') {
                const emailSummary = result.summary || {};
                const routing = result.routing || [];
                const threats = result.threats || [];
                const parsedHeaders = result.headers || [];

                summary['From'] = emailSummary.from || 'Unknown';
                summary['To'] = emailSummary.to || 'Unknown';
                summary['Subject'] = emailSummary.subject || 'N/A';
                summary['Date'] = emailSummary.date || 'Unknown';
                summary['Trust Score'] = `${emailSummary.trust_score ?? '?'}/100 (Grade ${emailSummary.trust_grade || '?'})`;
                summary['SPF'] = emailSummary.spf || 'Not Found';
                summary['DKIM'] = emailSummary.dkim || 'Not Found';
                summary['DMARC'] = emailSummary.dmarc || 'Not Found';
                summary['Server Hops'] = emailSummary.hops || 0;
                summary['Total Delivery Time'] = emailSummary.total_delay_seconds ? `${Math.round(emailSummary.total_delay_seconds)}s` : 'N/A';
                summary['Total Headers'] = result.total_headers || parsedHeaders.length;
                summary['Threats Detected'] = threats.length;
                summary['Return-Path'] = emailSummary.return_path || 'N/A';
                summary['Message-ID'] = emailSummary.message_id || 'N/A';

                tables.push({
                    title: 'Authentication Results',
                    headers: ['Check', 'Status', 'Details'],
                    rows: [
                        ['SPF (Sender Policy Framework)', emailSummary.spf || 'Not Found', emailSummary.spf_detail || '-'],
                        ['DKIM (DomainKeys Identified Mail)', emailSummary.dkim || 'Not Found', emailSummary.dkim_detail || '-'],
                        ['DMARC (Domain-based Auth)', emailSummary.dmarc || 'Not Found', emailSummary.dmarc_detail || '-'],
                    ]
                });

                if (routing.length > 0) {
                    tables.push({
                        title: `Routing Trace (${routing.length} Hops)`,
                        headers: ['Hop', 'From', 'To', 'IP', 'Protocol', 'TLS', 'Delay', 'Timestamp'],
                        rows: routing.map((hop: any) => [
                            hop.hop, hop.from_host || '-', hop.by_host || '-', hop.ip || '-',
                            hop.protocol || '-', hop.tls ? 'Yes' : 'No',
                            hop.delay_seconds != null ? `${hop.delay_seconds}s` : '-', hop.timestamp || '-'
                        ])
                    });
                }

                if (threats.length > 0) {
                    tables.push({
                        title: `Threat Indicators (${threats.length})`,
                        headers: ['Type', 'Severity', 'Description'],
                        rows: threats.map((t: any) => [
                            t.type.replace(/_/g, ' '), t.severity.toUpperCase(), t.description
                        ])
                    });
                }

                if (parsedHeaders.length > 0) {
                    tables.push({
                        title: `All Parsed Headers (${parsedHeaders.length})`,
                        headers: ['Status', 'Category', 'Header', 'Value', 'Analysis'],
                        rows: parsedHeaders.map((h: any) => [
                            (h.status || 'info').toUpperCase(),
                            (h.category || 'general').toUpperCase(),
                            h.key,
                            (h.value || '').substring(0, 120) + ((h.value || '').length > 120 ? '...' : ''),
                            h.analysis || '-'
                        ])
                    });
                }

                flags.push(
                    ...threats.map((t: any) => `[${t.severity.toUpperCase()}] ${t.type.replace(/_/g, ' ')}: ${t.description}`),
                    ...parsedHeaders
                        .filter((h: any) => h.status === 'danger')
                        .map((h: any) => `[DANGER] ${h.key}: ${h.analysis || h.value}`)
                );
            }
            // Handle Password Strength results
            else if (item.scan_type === 'PASSWORD_STRENGTH') {
                summary['Strength'] = `${result.score ?? 0}/4`;
                summary['Breach Status'] = result.breach_count > 0 ? `COMPROMISED (${result.breach_count})` : 'Clean';
            }
            // Handle Code Scan results
            else if (item.scan_type === 'CODE_SCAN') {
                summary['Language'] = result.language || 'Unknown';
                summary['Lines'] = result.lines_analyzed || 0;
                summary['Grade'] = result.grade || 'N/A';
                summary['Risk Score'] = `${result.risk_score || 0}/100`;
                summary['Risk Level'] = result.risk_level || 'Unknown';
                summary['Critical'] = result.summary?.critical || 0;
                summary['High'] = result.summary?.high || 0;
                summary['Medium'] = result.summary?.medium || 0;
                summary['Low'] = result.summary?.low || 0;

                if (result.vulnerabilities?.length > 0) {
                    tables.push({
                        title: 'Vulnerabilities',
                        headers: ['Line', 'Severity', 'Type', 'Category', 'CWE', 'Description'],
                        rows: result.vulnerabilities.map((v: any) => [
                            v.line || '-', v.severity, v.type, v.category || '', v.cwe_id || '', v.description
                        ])
                    });
                    const critical = result.vulnerabilities.filter((v: any) => v.severity === 'CRITICAL' || v.severity === 'HIGH');
                    if (critical.length > 0) flags.push(...critical.map((v: any) => `Line ${v.line}: ${v.type} — ${v.description}`));
                }
            }
            // Handle Ransomware Scan results
            else if (item.scan_type === 'RANSOMWARE_SCAN') {
                const formatBytes = (bytes: number): string => {
                    if (!bytes) return 'N/A';
                    if (bytes < 1024) return bytes + ' bytes';
                    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
                    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
                };

                summary['Verdict'] = result.ransomware_detected ? 'THREAT DETECTED' : 'CLEAN';
                summary['File Entropy'] = result.entropy?.toFixed(4) || 'N/A';
                summary['File Type'] = result.filetype || result.file_type || 'Unknown';
                summary['File Size'] = formatBytes(result.filesize || result.file_size || 0);

                tables.push({
                    title: 'Analysis Details',
                    headers: ['Metric', 'Value'],
                    rows: [
                        ['File Name', result.filename || item.target || 'N/A'],
                        ['File Size', formatBytes(result.filesize || result.file_size || 0)],
                        ['File Type', result.filetype || result.file_type || 'Unknown'],
                        ['Entropy', result.entropy?.toFixed(4) || 'N/A'],
                        ['Detection', result.ransomware_detected ? 'MALICIOUS' : 'CLEAN'],
                    ]
                });
                if (result.ransomware_detected) flags.push(result.details || 'Ransomware signatures detected');
            }
            // Handle Metadata Scan results
            else if (item.scan_type === 'METADATA_SCAN') {
                const formatBytes = (bytes: number): string => {
                    if (!bytes) return 'N/A';
                    if (bytes < 1024) return bytes + ' B';
                    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
                    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
                };

                summary['Content Type'] = result.content_type || 'N/A';
                summary['File Size'] = formatBytes(result.size_bytes);

                const fileInfoRows: (string | number)[][] = [
                    ['Filename', result.filename || 'N/A'],
                    ['Content Type', result.content_type || 'N/A'],
                    ['File Size', formatBytes(result.size_bytes)],
                    ['Created', result.created_at || 'N/A'],
                    ['Modified', result.modified_at || 'N/A'],
                ];
                if (result.is_image) {
                    fileInfoRows.push(
                        ['Format', result.format || 'N/A'],
                        ['Dimensions', `${result.dimensions?.[0]} × ${result.dimensions?.[1]} px`]
                    );
                }
                tables.push({ title: 'File Information', headers: ['Property', 'Value'], rows: fileInfoRows as string[][] });

                if (result.extended_metadata && Object.keys(result.extended_metadata).length > 0) {
                    tables.push({
                        title: 'Extended Metadata',
                        headers: ['Property', 'Value'],
                        rows: Object.entries(result.extended_metadata)
                            .filter(([_, v]) => v !== null && v !== 'None' && v !== '')
                            .map(([k, v]) => [k, String(v)])
                    });
                }

                // Privacy flags
                const privacyFlags: string[] = [];
                if (result.gps && Object.keys(result.gps).length > 0) {
                    privacyFlags.push('GPS Location Data: File contains GPS coordinates that reveal where it was created');
                }
                if (result.exif) {
                    const exifKeys = Object.keys(result.exif).map(k => k.toLowerCase());
                    if (exifKeys.some(k => k.includes('make') || k.includes('model'))) {
                        privacyFlags.push('Camera/Device Info: Device make and model are embedded in the file');
                    }
                    if (exifKeys.some(k => k.includes('software'))) {
                        privacyFlags.push('Software Info: Editing software information is stored in metadata');
                    }
                }
                if (result.extended_metadata) {
                    const extKeys = Object.keys(result.extended_metadata).map(k => k.toLowerCase());
                    if (extKeys.some(k => k.includes('author') || k.includes('creator') || k.includes('last_modified_by'))) {
                        privacyFlags.push('Author Identity: Author name or user identity is embedded');
                    }
                }
                if (privacyFlags.length > 0) flags.push(...privacyFlags);
            }
            // Handle WHOIS Lookup results
            else if (item.scan_type === 'WHOIS_LOOKUP') {
                summary['Registrar'] = result.registrar || 'N/A';
                summary['Created'] = result.creation_date ? new Date(result.creation_date).toLocaleDateString() : 'N/A';
                summary['Expires'] = result.expiration_date ? new Date(result.expiration_date).toLocaleDateString() : 'N/A';
                summary['Status'] = result.is_expired ? 'EXPIRED' : 'ACTIVE';
                summary['Days Until Expiry'] = result.days_until_expiry ?? 'N/A';
                summary['Organization'] = result.org || 'N/A';
                summary['Country'] = result.country || 'N/A';
                if (result.name_servers?.length) tables.push({ title: 'Name Servers', headers: ['Name Server'], rows: result.name_servers.map((ns: string) => [ns]) });
                if (result.is_expired) flags.push('Domain is EXPIRED');
            }
            // Handle DNS Lookup results
            else if (item.scan_type === 'DNS_LOOKUP') {
                summary['A Records'] = result.summary?.total_a_records ?? 0;
                summary['MX Records'] = result.summary?.total_mx_records ?? 0;
                summary['NS Records'] = result.summary?.total_ns_records ?? 0;
                summary['TXT Records'] = result.summary?.total_txt_records ?? 0;
                summary['Has IPv6'] = result.summary?.has_ipv6 ? 'Yes' : 'No';
                const recs = result.records || {};
                Object.entries(recs).forEach(([type, vals]: [string, any]) => {
                    if (!vals?.length) return;
                    tables.push({ title: `${type} Records`, headers: ['Value'], rows: vals.map((v: any) => [typeof v === 'string' ? v : v.value || v.exchange || JSON.stringify(v)]) });
                });
            }
            // Handle SSL Check results
            else if (item.scan_type === 'SSL_CHECK') {
                summary['Grade'] = result.grade || 'N/A';
                summary['Valid'] = result.valid ? 'Yes' : 'No';
                summary['Days Remaining'] = result.days_remaining ?? 'N/A';
                summary['Issued To'] = result.cert_details?.issued_to_cn || 'N/A';
                summary['Issued By'] = result.cert_details?.issued_by_cn || 'N/A';
                summary['Algorithm'] = result.cert_details?.signature_algorithm || 'N/A';
                summary['SAN Count'] = result.cert_details?.san_count ?? 0;
                if (result.cert_details?.sans?.length) tables.push({ title: 'Subject Alternative Names', headers: ['SAN'], rows: result.cert_details.sans.map((s: string) => [s]) });
                if (result.is_expired) flags.push('Certificate is EXPIRED');
                else if (result.days_remaining < 14) flags.push('Certificate expiring very soon');
            }
            // Handle other scan types (generic fallback)
            else {
                if (result.status) summary['Status'] = result.status;
                if (result.risk_score !== undefined) summary['Risk Score'] = `${result.risk_score}/100`;
                if (result.risk_level) summary['Risk Level'] = result.risk_level;
                if (result.score !== undefined) summary['Score'] = result.score;
                if (result.sha256) summary['SHA256'] = result.sha256;
                if (result.flags) flags.push(...result.flags);
                if (result.issues) flags.push(...result.issues);
            }

            exportToPDF({
                title: `${getScanTypeName(item.scan_type)} Report`,
                subtitle: item.target,
                summary,
                tables,
                flags,
            });
        } catch (err) {
            alert('Failed to export PDF');
            console.error(err);
        }
    };

    const closeModal = () => setSelectedItem(null);

    // Toggle Button (always shown)
    const toggleButton = (
        <button
            onClick={handleToggle}
            style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.625rem 1rem',
                background: isOpen ? 'hsl(var(--color-secondary-light))' : 'hsl(var(--bg-tertiary))',
                border: `1px solid ${isOpen ? 'hsla(var(--color-secondary), 0.3)' : 'hsl(var(--border-color))'}`,
                borderRadius: 'var(--radius-md)',
                color: isOpen ? 'hsl(var(--color-secondary))' : 'hsl(var(--text-secondary))',
                cursor: 'pointer',
                fontWeight: 600,
                fontSize: '0.875rem',
                transition: 'all 0.2s ease',
                width: '100%',
                justifyContent: 'center'
            }}
        >
            <History size={18} />
            {isOpen ? 'Hide Recent Scans' : 'Show Recent Scans'}
            {history.length > 0 && !isOpen && (
                <span style={{
                    background: 'hsl(var(--color-primary))',
                    color: 'white',
                    padding: '0.125rem 0.5rem',
                    borderRadius: 'var(--radius-full)',
                    fontSize: '0.7rem',
                    fontWeight: 700,
                    marginLeft: '0.25rem'
                }}>
                    {history.length}
                </span>
            )}
        </button>
    );

    // If not open, just show the toggle button
    if (!isOpen) {
        return <div style={{ marginTop: '1rem' }}>{toggleButton}</div>;
    }

    // Loading state
    if (loading && history.length === 0) {
        return (
            <div style={{ marginTop: '1rem' }}>
                {toggleButton}
                <Card style={{ marginTop: '1rem' }}>
                    <div style={{ padding: '2rem', textAlign: 'center', color: 'hsl(var(--text-muted))' }}>
                        Loading history...
                    </div>
                </Card>
            </div>
        );
    }

    // Empty state
    if (!loading && history.length === 0) {
        return (
            <div style={{ marginTop: '1rem' }}>
                {toggleButton}
                <Card style={{ marginTop: '1rem' }}>
                    <div style={{ 
                        padding: '3rem', 
                        textAlign: 'center', 
                        color: 'hsl(var(--text-muted))',
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        gap: '0.75rem'
                    }}>
                        <History size={48} style={{ opacity: 0.2 }} />
                        <p>No scan history found.</p>
                    </div>
                </Card>
            </div>
        );
    }

    return (
        <div style={{ marginTop: '1rem' }}>
            {toggleButton}
            <Card style={{ marginTop: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                    <h3 style={{ 
                        fontSize: '1rem', 
                        fontWeight: 700, 
                        color: 'hsl(var(--text-primary))',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.5rem'
                    }}>
                        <Clock size={18} style={{ color: 'hsl(var(--color-secondary))' }} />
                        Recent Scans ({history.length})
                    </h3>
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                        <button 
                            onClick={fetchHistory} 
                            style={{ 
                                padding: '0.5rem', 
                                background: 'transparent',
                                border: 'none',
                                color: 'hsl(var(--text-muted))',
                                cursor: 'pointer',
                                borderRadius: 'var(--radius-md)'
                            }}
                            title="Refresh"
                        >
                            <RefreshCw size={16} />
                        </button>
                        <button 
                            onClick={handleDeleteAll}
                            style={{
                                padding: '0.375rem 0.75rem',
                                fontSize: '0.75rem',
                                background: 'hsl(var(--color-error-light))',
                                color: 'hsl(var(--color-error))',
                                border: '1px solid hsla(var(--color-error), 0.3)',
                                borderRadius: 'var(--radius-md)',
                                cursor: 'pointer',
                                fontWeight: 600
                            }}
                        >
                            Clear History
                        </button>
                    </div>
                </div>
                
                <table className="data-table">
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Target</th>
                            <th>Type</th>
                            <th style={{ textAlign: 'right', width: '140px' }}>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {history.map((item) => (
                            <tr key={item.id}>
                                <td style={{ whiteSpace: 'nowrap', color: 'hsl(var(--text-secondary))' }}>
                                    {new Date(item.created_at).toLocaleDateString()}{' '}
                                    <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))' }}>
                                        {new Date(item.created_at).toLocaleTimeString()}
                                    </span>
                                </td>
                                <td style={{ 
                                    fontFamily: 'monospace', 
                                    maxWidth: '300px', 
                                    overflow: 'hidden', 
                                    textOverflow: 'ellipsis',
                                    whiteSpace: 'nowrap'
                                }} title={item.target}>
                                    {item.target}
                                </td>
                                <td>
                                    <span style={{ 
                                        fontSize: '0.7rem', 
                                        fontWeight: 700, 
                                        padding: '0.25rem 0.5rem', 
                                        borderRadius: 'var(--radius-sm)', 
                                        background: getScanTypeColor(item.scan_type).bg,
                                        color: getScanTypeColor(item.scan_type).text,
                                        border: `1px solid ${getScanTypeColor(item.scan_type).border}`
                                    }}>
                                        {getScanTypeName(item.scan_type)}
                                    </span>
                                </td>
                                <td style={{ textAlign: 'right' }}>
                                    <div style={{ display: 'flex', gap: '0.25rem', justifyContent: 'flex-end' }}>
                                        <button 
                                            onClick={() => handleViewResult(item)}
                                            style={{
                                                padding: '0.375rem',
                                                background: 'transparent',
                                                border: 'none',
                                                color: 'hsl(var(--color-primary))',
                                                cursor: 'pointer',
                                                borderRadius: 'var(--radius-sm)'
                                            }}
                                            title="View Details"
                                        >
                                            <Eye size={16} />
                                        </button>
                                        <button 
                                            onClick={() => handleExportItemPDF(item)}
                                            style={{
                                                padding: '0.375rem',
                                                background: 'transparent',
                                                border: 'none',
                                                color: 'hsl(var(--color-secondary))',
                                                cursor: 'pointer',
                                                borderRadius: 'var(--radius-sm)'
                                            }}
                                            title="Export PDF"
                                        >
                                            <Download size={16} />
                                        </button>
                                        <button 
                                            onClick={() => handleDelete(item.id)}
                                            style={{
                                                padding: '0.375rem',
                                                background: 'transparent',
                                                border: 'none',
                                                color: 'hsl(var(--text-muted))',
                                                cursor: 'pointer',
                                                borderRadius: 'var(--radius-sm)'
                                            }}
                                            title="Delete Record"
                                        >
                                            <Trash2 size={16} />
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </Card>


            {/* Result Modal - Using Portal */}
            {selectedItem && createPortal(
                <div style={{
                    position: 'fixed',
                    inset: 0,
                    background: 'rgba(0,0,0,0.7)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    zIndex: 9999,
                    padding: '2rem'
                }} onClick={closeModal}>
                    <div style={{
                        background: 'hsl(var(--bg-card))',
                        border: '1px solid hsl(var(--border-color))',
                        borderRadius: 'var(--radius-lg)',
                        width: '100%',
                        maxWidth: '900px',
                        maxHeight: '90vh',
                        display: 'flex',
                        flexDirection: 'column',
                        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)'
                    }} onClick={e => e.stopPropagation()}>
                        {/* Modal Header */}
                        <div style={{
                            padding: '1.5rem',
                            borderBottom: '1px solid hsl(var(--border-color))',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center'
                        }}>
                            <div>
                                <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.25rem' }}>
                                    {getScanTypeName(selectedItem.scan_type)} Results
                                </h3>
                                <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.875rem' }}>
                                    Target: {selectedItem.target}
                                </p>
                            </div>
                            <button 
                                onClick={closeModal}
                                style={{
                                    background: 'transparent',
                                    border: 'none',
                                    color: 'hsl(var(--text-muted))',
                                    cursor: 'pointer',
                                    padding: '0.5rem',
                                    borderRadius: 'var(--radius-full)',
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    transition: 'all 0.2s'
                                }}
                            >
                                <X size={24} />
                            </button>
                        </div>

                        {/* Modal Content */}
                        <div style={{
                            padding: '1.5rem',
                            overflowY: 'auto',
                            flex: 1
                        }}>
                            <ScanResultViewer 
                                scanType={selectedItem.scan_type}
                                target={selectedItem.target}
                                result={JSON.parse(selectedItem.result || '{}')}
                                createdAt={selectedItem.created_at}
                            />
                        </div>

                        {/* Modal Footer */}
                        <div style={{
                            padding: '1.5rem',
                            borderTop: '1px solid hsl(var(--border-color))',
                            display: 'flex',
                            justifyContent: 'flex-end',
                            gap: '1rem'
                        }}>
                            <button
                                onClick={() => handleExportItemPDF(selectedItem)}
                                style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '0.5rem',
                                    padding: '0.5rem 1rem',
                                    background: 'hsl(var(--color-secondary))',
                                    color: 'white',
                                    border: 'none',
                                    borderRadius: 'var(--radius-md)',
                                    cursor: 'pointer',
                                    fontWeight: 600
                                }}
                            >
                                <Download size={18} />
                                Export PDF
                            </button>
                            <button
                                onClick={closeModal}
                                style={{
                                    padding: '0.5rem 1rem',
                                    background: 'hsl(var(--bg-tertiary))',
                                    color: 'hsl(var(--text-primary))',
                                    border: '1px solid hsl(var(--border-color))',
                                    borderRadius: 'var(--radius-md)',
                                    cursor: 'pointer',
                                    fontWeight: 600
                                }}
                            >
                                Close
                            </button>
                        </div>
                    </div>
                </div>,
                document.body
            )}
        </div>
    );
};
