
import React, { useRef, useState } from 'react';
import { Upload, X } from 'lucide-react';
import { Button } from './Button';

interface FileUploadProps {
    label?: string;
    accept?: string;
    onFileSelect: (file: File | null) => void;
    currentFile: File | null;
}

export const FileUpload: React.FC<FileUploadProps> = ({ label = "Upload File", accept, onFileSelect, currentFile }) => {
    const inputRef = useRef<HTMLInputElement>(null);
    const [dragActive, setDragActive] = useState(false);

    const handleDrag = (e: React.DragEvent) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.type === "dragenter" || e.type === "dragover") {
            setDragActive(true);
        } else if (e.type === "dragleave") {
            setDragActive(false);
        }
    };

    const handleDrop = (e: React.DragEvent) => {
        e.preventDefault();
        e.stopPropagation();
        setDragActive(false);
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            onFileSelect(e.dataTransfer.files[0]);
        }
    };

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        e.preventDefault();
        if (e.target.files && e.target.files[0]) {
            onFileSelect(e.target.files[0]);
        }
    };

    return (
        <div className="flex flex-col gap-2 w-full">
            <span className="text-sm font-bold uppercase tracking-wider text-[hsl(var(--color-primary))]">{label}</span>
            
            {!currentFile ? (
                <div 
                    className={`
                        flex flex-col items-center justify-center p-8 
                        border-2 border-dashed rounded-lg cursor-pointer
                        transition-all duration-300
                        ${dragActive 
                            ? 'border-[hsl(var(--color-primary))] bg-[hsl(var(--color-primary))] bg-opacity-10' 
                            : 'border-[hsl(var(--border-color))] hover:border-[hsl(var(--color-primary))] hover:bg-[hsl(var(--bg-secondary))]'
                        }
                    `}
                    onDragEnter={handleDrag}
                    onDragLeave={handleDrag}
                    onDragOver={handleDrag}
                    onDrop={handleDrop}
                    onClick={() => inputRef.current?.click()}
                >
                    <input 
                        ref={inputRef}
                        type="file" 
                        accept={accept}
                        className="hidden" 
                        onChange={handleChange}
                    />
                    <Upload size={32} className={`mb-2 ${dragActive ? 'text-[hsl(var(--color-primary))]' : 'text-[hsl(var(--text-secondary))]'}`} />
                    <p className="text-sm font-medium">Click to upload or drag & drop</p>
                    <p className="text-xs text-[hsl(var(--text-secondary))] mt-1">
                        {accept ? `Supported files: ${accept}` : 'All files supported'}
                    </p>
                </div>
            ) : (
                <div className="flex items-center justify-between p-4 bg-[hsl(var(--bg-secondary))] bg-opacity-50 rounded-lg border border-[hsl(var(--color-primary))]">
                    <div className="flex items-center gap-3 overflow-hidden">
                        <div className="p-2 bg-[hsl(var(--color-primary))] bg-opacity-20 rounded">
                            <Upload size={18} className="text-[hsl(var(--color-primary))]" />
                        </div>
                        <div className="flex flex-col overflow-hidden">
                            <span className="text-sm font-medium truncate w-[200px]">{currentFile.name}</span>
                            <span className="text-xs text-[hsl(var(--text-secondary))]">{(currentFile.size / 1024).toFixed(2)} KB</span>
                        </div>
                    </div>
                    <Button 
                        type="button" 
                        variant="ghost" 
                        size="sm" 
                        onClick={() => {
                            onFileSelect(null);
                            if (inputRef.current) inputRef.current.value = '';
                        }}
                    >
                        <X size={18} />
                    </Button>
                </div>
            )}
        </div>
    );
};
