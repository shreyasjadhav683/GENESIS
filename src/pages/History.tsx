import React, { useState } from 'react';
import { ScanHistoryTable } from '../components/ScanHistoryTable';
import { Clock, Filter } from 'lucide-react';

export const History: React.FC = () => {
    const [scanTypeFilter, setScanTypeFilter] = useState<string>('ALL');

    const scanTypes = [
        { id: 'ALL', label: 'All Scans' },
        { id: 'IP', label: 'IP Scans' },
        { id: 'URL', label: 'URL Scans' },
        { id: 'FILE', label: 'File Integrity' },
        { id: 'BROWSER_EXTENSIONS', label: 'Browser Ext' },
        { id: 'CODE', label: 'Code Analysis' },
        { id: 'RANSOMWARE', label: 'Ransomware' },
        { id: 'EMAIL', label: 'Email Headers' },
        { id: 'SECURITY_HEADERS', label: 'Security Headers' },
        { id: 'PHISHING', label: 'Phishing Check' },
        { id: 'PASSWORD', label: 'Password Strength' },
    ];

    const currentFilter = scanTypeFilter === 'ALL' ? undefined : scanTypeFilter as any;

    return (
        <div className="p-6 max-w-7xl mx-auto space-y-6">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                    <h1 className="text-2xl font-bold flex items-center gap-3">
                        <Clock className="w-8 h-8 text-primary" />
                        Activity Logs & Reports
                    </h1>
                    <p className="text-secondary mt-1">
                        View comprehensive history of all security scans and analysis reports.
                    </p>
                </div>
            </div>

            {/* Filters */}
            <div className="flex items-center gap-4 overflow-x-auto pb-2 scrollbar-thin">
                <div className="flex items-center gap-2 text-sm font-semibold text-secondary whitespace-nowrap">
                    <Filter size={16} /> Filter by:
                </div>
                {scanTypes.map(type => (
                    <button
                        key={type.id}
                        onClick={() => setScanTypeFilter(type.id)}
                        className={`px-3 py-1.5 rounded-full text-sm font-medium transition-colors whitespace-nowrap ${
                            scanTypeFilter === type.id
                                ? 'bg-primary text-white shadow-lg shadow-primary/20'
                                : 'bg-card hover:bg-secondary/10 text-secondary border border-border'
                        }`}
                    >
                        {type.label}
                    </button>
                ))}
            </div>

            {/* History Table */}
            <ScanHistoryTable type={currentFilter} alwaysOpen={true} />
        </div>
    );
};
