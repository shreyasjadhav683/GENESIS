import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

export interface ExportData {
    title: string;
    subtitle?: string;
    timestamp?: string;
    summary?: Record<string, string | number>;
    tables?: Array<{
        title: string;
        headers: string[];
        rows: (string | number)[][];
    }>;
    flags?: string[];
    rawData?: Record<string, any>;
}

export const exportToPDF = (data: ExportData) => {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    let yPos = 20;

    // Title
    doc.setFontSize(20);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(40, 40, 40);
    doc.text(data.title, pageWidth / 2, yPos, { align: 'center' });
    yPos += 10;

    // Subtitle
    if (data.subtitle) {
        doc.setFontSize(12);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(100, 100, 100);
        doc.text(data.subtitle, pageWidth / 2, yPos, { align: 'center' });
        yPos += 8;
    }

    // Timestamp
    doc.setFontSize(10);
    doc.setTextColor(150, 150, 150);
    const timestamp = data.timestamp || new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
    doc.text(`Generated: ${timestamp}`, pageWidth / 2, yPos, { align: 'center' });
    yPos += 15;

    // Separator line
    doc.setDrawColor(200, 200, 200);
    doc.line(20, yPos, pageWidth - 20, yPos);
    yPos += 10;

    // Summary section
    if (data.summary && Object.keys(data.summary).length > 0) {
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(40, 40, 40);
        doc.text('Summary', 20, yPos);
        yPos += 8;

        const summaryData = Object.entries(data.summary).map(([key, value]) => [key, String(value)]);
        autoTable(doc, {
            startY: yPos,
            head: [['Property', 'Value']],
            body: summaryData,
            theme: 'striped',
            headStyles: { fillColor: [59, 130, 246] },
            margin: { left: 20, right: 20 },
        });
        yPos = (doc as any).lastAutoTable.finalY + 15;
    }

    // Tables
    if (data.tables && data.tables.length > 0) {
        for (const table of data.tables) {
            if (yPos > 250) {
                doc.addPage();
                yPos = 20;
            }

            doc.setFontSize(14);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(40, 40, 40);
            doc.text(table.title, 20, yPos);
            yPos += 8;

            autoTable(doc, {
                startY: yPos,
                head: [table.headers],
                body: table.rows,
                theme: 'striped',
                headStyles: { fillColor: [59, 130, 246] },
                margin: { left: 20, right: 20 },
                styles: { fontSize: 9 },
            });
            yPos = (doc as any).lastAutoTable.finalY + 15;
        }
    }

    // Flags/Alerts
    if (data.flags && data.flags.length > 0) {
        if (yPos > 250) {
            doc.addPage();
            yPos = 20;
        }

        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(40, 40, 40);
        doc.text('Findings & Alerts', 20, yPos);
        yPos += 8;

        const flagsData = data.flags.map((flag, idx) => [idx + 1, flag]);
        autoTable(doc, {
            startY: yPos,
            head: [['#', 'Finding']],
            body: flagsData,
            theme: 'striped',
            headStyles: { fillColor: [239, 68, 68] },
            margin: { left: 20, right: 20 },
        });
        yPos = (doc as any).lastAutoTable.finalY + 15;
    }

    // Footer
    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFontSize(8);
        doc.setTextColor(150, 150, 150);
        doc.text(
            `Genesis Security Dashboard - Page ${i} of ${pageCount}`,
            pageWidth / 2,
            doc.internal.pageSize.getHeight() - 10,
            { align: 'center' }
        );
    }

    // Save the PDF
    const filename = `${data.title.replace(/[^a-z0-9]/gi, '_').toLowerCase()}_${new Date().toISOString().split('T')[0]}.pdf`;
    doc.save(filename);
};

export const exportToJSON = (data: any, filename: string) => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${filename}_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
};
