import React, { useState, useRef, useEffect } from 'react';
import { 
    Send, Bot, User, Sparkles, MessageSquare, Plus, Copy, Check,
    Shield, Bug, Lock, Globe, AlertTriangle, Zap, X
} from 'lucide-react';
import { api } from '../../services/api';

interface ChatMessage {
    role: 'user' | 'assistant';
    content: string;
}

interface ChatSession {
    id: number;
    title: string;
    created_at: string;
}

// ── Markdown Renderer ─────────────────────────────────────
const renderMarkdown = (text: string) => {
    const lines = text.split('\n');
    const elements: React.ReactNode[] = [];
    let i = 0;

    while (i < lines.length) {
        const line = lines[i];

        // Fenced code blocks
        if (line.trim().startsWith('```')) {
            const lang = line.trim().slice(3).trim();
            const codeLines: string[] = [];
            i++;
            while (i < lines.length && !lines[i].trim().startsWith('```')) {
                codeLines.push(lines[i]);
                i++;
            }
            i++; // skip closing ```
            elements.push(
                <div key={elements.length} style={{ margin: '0.6rem 0' }}>
                    {lang && (
                        <div style={{
                            fontSize: '0.65rem', fontWeight: 700, textTransform: 'uppercase',
                            padding: '0.25rem 0.75rem', background: 'hsla(var(--color-primary), 0.12)',
                            color: 'hsl(var(--color-primary))', borderRadius: '8px 8px 0 0',
                            display: 'inline-block', letterSpacing: '0.04em'
                        }}>{lang}</div>
                    )}
                    <pre style={{
                        margin: 0, padding: '0.85rem 1rem',
                        background: 'hsl(220, 20%, 10%)',
                        borderRadius: lang ? '0 8px 8px 8px' : '8px',
                        border: '1px solid hsla(var(--border-color), 0.5)',
                        overflowX: 'auto', fontSize: '0.82rem', lineHeight: 1.6,
                        fontFamily: "'Fira Code', 'Cascadia Code', 'Consolas', monospace",
                        color: '#e2e8f0'
                    }}>
                        <code>{codeLines.join('\n')}</code>
                    </pre>
                </div>
            );
            continue;
        }

        // Tables
        if (line.includes('|') && line.trim().startsWith('|')) {
            const tableRows: string[] = [];
            while (i < lines.length && lines[i].includes('|') && lines[i].trim().startsWith('|')) {
                tableRows.push(lines[i]);
                i++;
            }
            if (tableRows.length >= 2) {
                const parseRow = (row: string) =>
                    row.split('|').map(c => c.trim()).filter(c => c && !c.match(/^[-:]+$/));
                const headers = parseRow(tableRows[0]);
                const isSeparator = (row: string) => row.replace(/[|\s:-]/g, '') === '';
                const bodyStart = isSeparator(tableRows[1]) ? 2 : 1;
                const bodyRows = tableRows.slice(bodyStart).map(parseRow);

                elements.push(
                    <div key={elements.length} style={{ margin: '0.6rem 0', overflowX: 'auto', borderRadius: '8px', border: '1px solid hsla(var(--border-color), 0.5)' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
                            <thead>
                                <tr style={{ background: 'hsla(var(--color-primary), 0.06)' }}>
                                    {headers.map((h, hi) => (
                                        <th key={hi} style={{
                                            padding: '0.5rem 0.75rem', fontWeight: 700,
                                            borderBottom: '1px solid hsla(var(--border-color), 0.5)',
                                            textAlign: 'left', whiteSpace: 'nowrap',
                                            color: 'hsl(var(--text-primary))'
                                        }}>{formatInline(h)}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {bodyRows.map((row, ri) => (
                                    <tr key={ri} style={{ background: ri % 2 === 0 ? 'transparent' : 'hsla(var(--bg-secondary), 0.3)' }}>
                                        {row.map((cell, ci) => (
                                            <td key={ci} style={{
                                                padding: '0.4rem 0.75rem',
                                                borderBottom: '1px solid hsla(var(--border-color), 0.3)',
                                            }}>{formatInline(cell)}</td>
                                        ))}
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                );
            }
            continue;
        }

        // Empty line
        if (line.trim() === '') {
            elements.push(<div key={elements.length} style={{ height: '0.35rem' }} />);
            i++;
            continue;
        }

        // Headers
        if (line.startsWith('### ')) {
            elements.push(
                <h4 key={elements.length} style={{ 
                    fontSize: '0.9rem', fontWeight: 700, margin: '0.75rem 0 0.3rem',
                    color: 'hsl(var(--text-primary))',
                    display: 'flex', alignItems: 'center', gap: '0.4rem'
                }}>
                    <span style={{ width: '3px', height: '14px', background: 'hsl(var(--color-primary))', borderRadius: '2px', flexShrink: 0 }} />
                    {formatInline(line.slice(4))}
                </h4>
            );
            i++; continue;
        }
        if (line.startsWith('## ')) {
            elements.push(
                <h3 key={elements.length} style={{ 
                    fontSize: '1rem', fontWeight: 800, margin: '0.85rem 0 0.35rem',
                    color: 'hsl(var(--text-primary))',
                    paddingBottom: '0.35rem',
                    borderBottom: '1px solid hsla(var(--border-color), 0.3)'
                }}>{formatInline(line.slice(3))}</h3>
            );
            i++; continue;
        }
        if (line.startsWith('# ')) {
            elements.push(
                <h2 key={elements.length} style={{ 
                    fontSize: '1.1rem', fontWeight: 800, margin: '0.85rem 0 0.35rem',
                    color: 'hsl(var(--text-primary))'
                }}>{formatInline(line.slice(2))}</h2>
            );
            i++; continue;
        }

        // Numbered list
        const numMatch = line.match(/^(\d+)\.\s+(.*)/);
        if (numMatch) {
            elements.push(
                <div key={elements.length} style={{ display: 'flex', gap: '0.5rem', margin: '0.2rem 0', paddingLeft: '0.25rem' }}>
                    <span style={{ 
                        color: 'hsl(var(--color-primary))', fontWeight: 700, 
                        minWidth: '1.4rem', flexShrink: 0,
                        fontSize: '0.85rem'
                    }}>{numMatch[1]}.</span>
                    <span style={{ flex: 1, lineHeight: 1.6 }}>{formatInline(numMatch[2])}</span>
                </div>
            );
            i++; continue;
        }

        // Bullet list
        if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
            const indent = line.length - line.trimStart().length;
            const content = line.trim().slice(2);
            elements.push(
                <div key={elements.length} style={{ display: 'flex', gap: '0.5rem', margin: '0.2rem 0', paddingLeft: `${0.25 + indent * 0.5}rem` }}>
                    <span style={{ 
                        color: 'hsl(var(--color-primary))', fontWeight: 700, flexShrink: 0,
                        fontSize: '0.7rem', marginTop: '0.35rem'
                    }}>●</span>
                    <span style={{ flex: 1, lineHeight: 1.6 }}>{formatInline(content)}</span>
                </div>
            );
            i++; continue;
        }

        // Regular paragraph
        elements.push(
            <p key={elements.length} style={{ margin: '0.15rem 0', lineHeight: 1.65 }}>
                {formatInline(line)}
            </p>
        );
        i++;
    }

    return elements;
};

// Inline formatting: bold, italic, inline code, links
const formatInline = (text: string): React.ReactNode => {
    const parts: React.ReactNode[] = [];
    const regex = /(\*\*(.+?)\*\*)|(\*(.+?)\*)|(`(.+?)`)|(\[(.+?)\]\((.+?)\))/g;
    let lastIndex = 0;
    let match;

    while ((match = regex.exec(text)) !== null) {
        if (match.index > lastIndex) {
            parts.push(text.slice(lastIndex, match.index));
        }
        if (match[1]) {
            parts.push(<strong key={parts.length} style={{ fontWeight: 700, color: 'hsl(var(--text-primary))' }}>{match[2]}</strong>);
        } else if (match[3]) {
            parts.push(<em key={parts.length} style={{ fontStyle: 'italic' }}>{match[4]}</em>);
        } else if (match[5]) {
            parts.push(
                <code key={parts.length} style={{
                    padding: '0.12rem 0.4rem', borderRadius: '5px',
                    background: 'hsla(var(--color-primary), 0.08)',
                    border: '1px solid hsla(var(--color-primary), 0.15)',
                    fontFamily: "'Fira Code', 'Consolas', monospace",
                    fontSize: '0.84em', fontWeight: 500,
                    color: 'hsl(var(--color-primary))'
                }}>{match[6]}</code>
            );
        } else if (match[7]) {
            parts.push(
                <a key={parts.length} href={match[9]} target="_blank" rel="noopener noreferrer"
                    style={{ color: 'hsl(var(--color-primary))', textDecoration: 'underline', fontWeight: 500 }}>
                    {match[8]}
                </a>
            );
        }
        lastIndex = regex.lastIndex;
    }

    if (lastIndex < text.length) {
        parts.push(text.slice(lastIndex));
    }

    return parts.length === 1 && typeof parts[0] === 'string' ? parts[0] : <>{parts}</>;
};


// ── Suggestion Chips ──────────────────────────────────────
const SUGGESTIONS = [
    { label: 'SQL Injection', icon: <Bug size={14} />, query: 'Explain SQL injection and how to prevent it' },
    { label: 'XSS Prevention', icon: <AlertTriangle size={14} />, query: 'What is XSS and how do I protect my app?' },
    { label: 'Password Policy', icon: <Lock size={14} />, query: 'What is a strong password policy?' },
    { label: 'OWASP Top 10', icon: <Shield size={14} />, query: 'Explain the OWASP Top 10' },
    { label: 'API Security', icon: <Globe size={14} />, query: 'Best practices for securing REST APIs' },
    { label: 'Ransomware Response', icon: <Zap size={14} />, query: 'How to respond to a ransomware attack?' },
];


// ── Copy Button Component ─────────────────────────────────
const CopyButton = ({ text }: { text: string }) => {
    const [copied, setCopied] = useState(false);
    const handleCopy = () => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };
    return (
        <button onClick={handleCopy} title={copied ? 'Copied!' : 'Copy response'} style={{
            background: copied ? 'hsla(var(--color-success), 0.1)' : 'hsla(var(--text-muted), 0.05)',
            border: '1px solid transparent', cursor: 'pointer',
            color: copied ? 'hsl(var(--color-success))' : 'hsl(var(--text-muted))',
            padding: '0.3rem 0.5rem', borderRadius: '6px', display: 'flex', alignItems: 'center',
            gap: '0.3rem', fontSize: '0.7rem', fontWeight: 500,
            transition: 'all 0.2s'
        }}>
            {copied ? <><Check size={12} /> Copied</> : <><Copy size={12} /> Copy</>}
        </button>
    );
};


// ── Chat Item Component (with proper hover delete) ────────
const ChatItem = ({ chat, isActive, onSelect, onDelete }: {
    chat: ChatSession;
    isActive: boolean;
    onSelect: () => void;
    onDelete: (e: React.MouseEvent) => void;
}) => {
    const [hovered, setHovered] = useState(false);

    return (
        <div
            onMouseEnter={() => setHovered(true)}
            onMouseLeave={() => setHovered(false)}
            onClick={onSelect}
            style={{
                padding: '0.55rem 0.6rem',
                borderRadius: '10px',
                cursor: 'pointer',
                background: isActive 
                    ? 'hsla(var(--color-primary), 0.12)' 
                    : hovered ? 'hsla(var(--text-primary), 0.04)' : 'transparent',
                border: isActive ? '1px solid hsla(var(--color-primary), 0.2)' : '1px solid transparent',
                color: isActive ? 'hsl(var(--color-primary))' : 'hsl(var(--text-secondary))',
                display: 'flex', alignItems: 'center', gap: '0.5rem',
                transition: 'all 0.15s ease', fontSize: '0.82rem', flexShrink: 0,
            }}
        >
            <MessageSquare size={14} style={{ flexShrink: 0, opacity: 0.6 }} />
            <div style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', flex: 1, fontWeight: isActive ? 600 : 400 }}>
                {chat.title}
            </div>
            {hovered && (
                <button
                    onClick={onDelete}
                    style={{
                        background: 'hsla(var(--color-error), 0.08)',
                        border: 'none', cursor: 'pointer',
                        color: 'hsl(var(--color-error))',
                        padding: '0.25rem', borderRadius: '6px',
                        display: 'flex', alignItems: 'center',
                        flexShrink: 0, transition: 'all 0.15s'
                    }}
                    title="Delete chat"
                >
                    <X size={14} />
                </button>
            )}
        </div>
    );
};


// ── Main Component ────────────────────────────────────────
export const AiAssistant = () => {
    const [query, setQuery] = useState('');
    const [messages, setMessages] = useState<ChatMessage[]>([]);
    const [chats, setChats] = useState<ChatSession[]>([]);
    const [currentChatId, setCurrentChatId] = useState<number | null>(null);
    const [loading, setLoading] = useState(false);
    const messagesEndRef = useRef<HTMLDivElement>(null);
    const textareaRef = useRef<HTMLTextAreaElement>(null);

    useEffect(() => { fetchChats(); }, []);

    useEffect(() => {
        if (currentChatId) {
            fetchMessages(currentChatId);
        } else {
            setMessages([]);
        }
    }, [currentChatId]);

    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    useEffect(() => {
        if (textareaRef.current) {
            textareaRef.current.style.height = 'auto';
            textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, 150) + 'px';
        }
    }, [query]);

    const fetchChats = async () => {
        try {
            const response = await api.get('/ai/chats');
            setChats(response.data);
        } catch (error) {
            console.error('Failed to fetch chats:', error);
        }
    };

    const fetchMessages = async (chatId: number) => {
        try {
            const response = await api.get(`/ai/chats/${chatId}/messages`);
            setMessages(response.data);
        } catch (error) {
            console.error('Failed to fetch messages:', error);
        }
    };

    const createNewChat = async (firstMessage?: string) => {
        const title = firstMessage ? (firstMessage.slice(0, 30) + (firstMessage.length > 30 ? '...' : '')) : 'New Chat';
        try {
            const response = await api.post('/ai/chats?title=' + encodeURIComponent(title));
            const newChat = response.data;
            setChats(prev => [newChat, ...prev]);
            setCurrentChatId(newChat.id);
            return newChat.id;
        } catch (error) {
            console.error('Failed to create chat:', error);
        }
        return null;
    };

    const deleteChat = async (chatId: number, e: React.MouseEvent) => {
        e.stopPropagation();
        try {
            await api.delete(`/ai/chats/${chatId}`);
            setChats(prev => prev.filter(c => c.id !== chatId));
            if (currentChatId === chatId) {
                setCurrentChatId(null);
            }
        } catch (error) {
            console.error('Failed to delete chat:', error);
        }
    };

    const handleSend = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!query.trim() || loading) return;

        const userContent = query.trim();
        const userMessage: ChatMessage = { role: 'user', content: userContent };
        setMessages(prev => [...prev, userMessage]);
        setQuery('');
        setLoading(true);

        let activeChatId: number | null = currentChatId;
        if (!activeChatId) {
            activeChatId = await createNewChat(userContent);
        }

        try {
            const response = await api.post('/ai/assistant', {
                query: userContent,
                chat_id: activeChatId
            });
            const botMessage: ChatMessage = { role: 'assistant', content: response.data.response };
            setMessages(prev => [...prev, botMessage]);
        } catch (err: any) {
            const errorMessage: ChatMessage = {
                role: 'assistant',
                content: `⚠️ **Error:** ${err.response?.data?.detail || err.message || 'Failed to get response'}. Please try again.`
            };
            setMessages(prev => [...prev, errorMessage]);
        } finally {
            setLoading(false);
        }
    };

    const handleSuggestionClick = (suggestionQuery: string) => {
        const userMessage: ChatMessage = { role: 'user', content: suggestionQuery };
        setMessages(prev => [...prev, userMessage]);
        setLoading(true);

        (async () => {
            let activeChatId = currentChatId;
            if (!activeChatId) {
                activeChatId = await createNewChat(suggestionQuery);
            }
            try {
                const response = await api.post('/ai/assistant', {
                    query: suggestionQuery,
                    chat_id: activeChatId
                });
                setMessages(prev => [...prev, { role: 'assistant', content: response.data.response }]);
            } catch (err: any) {
                setMessages(prev => [...prev, {
                    role: 'assistant',
                    content: `⚠️ **Error:** ${err.response?.data?.detail || err.message || 'Failed to get response'}`
                }]);
            } finally {
                setLoading(false);
            }
        })();
    };

    const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSend(e as unknown as React.FormEvent);
        }
    };

    const isEmptyState = messages.length === 0;

    return (
        <div style={{ 
            maxWidth: '1200px', margin: '0 auto', 
            height: 'calc(100vh - 140px)', 
            display: 'flex', gap: '1rem', padding: '0.75rem', overflow: 'hidden' 
        }}>

            {/* ── Sidebar ────────────────────────────────── */}
            <div style={{ 
                width: '250px', display: 'flex', flexDirection: 'column', gap: '0.5rem', 
                height: '100%', overflow: 'hidden', flexShrink: 0,
                background: 'hsla(var(--bg-card), 0.5)',
                borderRadius: '16px', padding: '0.75rem',
                border: '1px solid hsla(var(--border-color), 0.5)'
            }}>
                <button
                    onClick={() => setCurrentChatId(null)}
                    style={{
                        display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem',
                        width: '100%', padding: '0.65rem',
                        background: 'hsla(var(--color-primary), 0.1)',
                        border: '1px dashed hsla(var(--color-primary), 0.3)',
                        borderRadius: '10px', cursor: 'pointer',
                        color: 'hsl(var(--color-primary))',
                        fontWeight: 600, fontSize: '0.85rem',
                        transition: 'all 0.15s', flexShrink: 0
                    }}
                >
                    <Plus size={16} /> New Chat
                </button>

                <div style={{
                    flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column',
                    gap: '0.15rem', minHeight: 0, paddingRight: '0.15rem',
                    marginTop: '0.25rem'
                }} className="ai-scrollbar">
                    {chats.length > 0 && (
                        <div style={{ 
                            fontSize: '0.68rem', fontWeight: 700, color: 'hsl(var(--text-muted))', 
                            padding: '0.4rem 0.5rem 0.3rem', textTransform: 'uppercase', 
                            letterSpacing: '0.06em', flexShrink: 0 
                        }}>
                            Recent Chats
                        </div>
                    )}
                    {chats.map(chat => (
                        <ChatItem
                            key={chat.id}
                            chat={chat}
                            isActive={currentChatId === chat.id}
                            onSelect={() => setCurrentChatId(chat.id)}
                            onDelete={(e) => deleteChat(chat.id, e)}
                        />
                    ))}
                    {chats.length === 0 && (
                        <div style={{ 
                            textAlign: 'center', padding: '2rem 1rem', 
                            color: 'hsl(var(--text-muted))', fontSize: '0.78rem' 
                        }}>
                            No chats yet. Start a conversation!
                        </div>
                    )}
                </div>
            </div>

            {/* ── Main Chat Area ─────────────────────────── */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden', minWidth: 0 }}>
                {/* Header */}
                <div style={{ 
                    display: 'flex', alignItems: 'center', gap: '0.75rem', 
                    padding: '0.5rem 0.25rem 0.75rem',
                    flexShrink: 0 
                }}>
                    <div style={{
                        width: '38px', height: '38px', borderRadius: '12px',
                        background: 'linear-gradient(135deg, hsl(var(--color-primary)) 0%, hsla(var(--color-primary), 0.5) 100%)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        color: 'white', boxShadow: '0 4px 15px hsla(var(--color-primary), 0.25)'
                    }}>
                        <Sparkles size={18} />
                    </div>
                    <div>
                        <h1 style={{ fontSize: '1.15rem', fontWeight: 800, margin: 0, letterSpacing: '-0.01em' }}>GENESIS AI</h1>
                        <p style={{ fontSize: '0.72rem', color: 'hsl(var(--text-muted))', margin: 0, fontWeight: 500 }}>
                            Security Assistant • Powered by Gemini
                        </p>
                    </div>
                </div>

                {/* Chat Body */}
                <div style={{ 
                    flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden',
                    background: 'hsl(var(--bg-card))',
                    borderRadius: '16px',
                    border: '1px solid hsla(var(--border-color), 0.5)',
                    boxShadow: '0 4px 24px rgba(0,0,0,0.12)'
                }}>
                    {/* Messages or Empty State */}
                    <div className="ai-scrollbar" style={{
                        flex: 1, overflowY: 'auto', padding: '1.25rem',
                        display: 'flex', flexDirection: 'column', gap: '1rem', minHeight: 0
                    }}>
                        {isEmptyState ? (
                            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '1.75rem', padding: '2rem' }}>
                                {/* Logo */}
                                <div style={{ position: 'relative' }}>
                                    <div style={{
                                        width: '72px', height: '72px', borderRadius: '20px',
                                        background: 'linear-gradient(135deg, hsl(var(--color-primary)), hsla(var(--color-primary), 0.4))',
                                        display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white',
                                        boxShadow: '0 12px 32px hsla(var(--color-primary), 0.25)'
                                    }}>
                                        <Sparkles size={32} />
                                    </div>
                                    <div style={{
                                        position: 'absolute', bottom: '-4px', right: '-4px',
                                        width: '24px', height: '24px', borderRadius: '50%',
                                        background: 'hsl(var(--color-success))', border: '3px solid hsl(var(--bg-card))',
                                        display: 'flex', alignItems: 'center', justifyContent: 'center'
                                    }}>
                                        <Shield size={11} style={{ color: 'white' }} />
                                    </div>
                                </div>

                                <div style={{ textAlign: 'center' }}>
                                    <h2 style={{ fontSize: '1.35rem', fontWeight: 800, margin: '0 0 0.5rem', letterSpacing: '-0.01em' }}>
                                        How can I help you today?
                                    </h2>
                                    <p style={{ color: 'hsl(var(--text-muted))', fontSize: '0.88rem', maxWidth: '420px', lineHeight: 1.5 }}>
                                        Ask about cybersecurity threats, best practices, compliance, or Genesis tool usage.
                                    </p>
                                </div>

                                {/* Suggestion Chips */}
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', justifyContent: 'center', maxWidth: '520px' }}>
                                    {SUGGESTIONS.map((s, idx) => (
                                        <button
                                            key={idx}
                                            onClick={() => handleSuggestionClick(s.query)}
                                            style={{
                                                display: 'flex', alignItems: 'center', gap: '0.4rem',
                                                padding: '0.5rem 0.9rem', borderRadius: '100px',
                                                border: '1px solid hsla(var(--border-color), 0.6)',
                                                background: 'hsla(var(--bg-secondary), 0.5)',
                                                color: 'hsl(var(--text-secondary))',
                                                cursor: 'pointer', fontSize: '0.8rem', fontWeight: 500,
                                                transition: 'all 0.2s', backdropFilter: 'blur(4px)'
                                            }}
                                            onMouseEnter={(e) => {
                                                e.currentTarget.style.borderColor = 'hsl(var(--color-primary))';
                                                e.currentTarget.style.color = 'hsl(var(--color-primary))';
                                                e.currentTarget.style.background = 'hsla(var(--color-primary), 0.06)';
                                                e.currentTarget.style.transform = 'translateY(-1px)';
                                            }}
                                            onMouseLeave={(e) => {
                                                e.currentTarget.style.borderColor = 'hsla(var(--border-color), 0.6)';
                                                e.currentTarget.style.color = 'hsl(var(--text-secondary))';
                                                e.currentTarget.style.background = 'hsla(var(--bg-secondary), 0.5)';
                                                e.currentTarget.style.transform = 'translateY(0)';
                                            }}
                                        >
                                            {s.icon}
                                            {s.label}
                                        </button>
                                    ))}
                                </div>
                            </div>
                        ) : (
                            <>
                                {messages.map((msg, idx) => (
                                    <div key={idx} style={{
                                        display: 'flex',
                                        justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start',
                                        animation: 'fadeIn 0.3s ease'
                                    }}>
                                        <div style={{
                                            display: 'flex', gap: '0.6rem',
                                            maxWidth: msg.role === 'user' ? '70%' : '90%',
                                            flexDirection: msg.role === 'user' ? 'row-reverse' : 'row'
                                        }}>
                                            {/* Avatar */}
                                            <div style={{
                                                width: '28px', height: '28px', borderRadius: '10px',
                                                flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
                                                background: msg.role === 'user'
                                                    ? 'hsl(var(--color-secondary))'
                                                    : 'linear-gradient(135deg, hsl(var(--color-primary)), hsla(var(--color-primary), 0.6))',
                                                color: 'white', marginTop: '4px',
                                                fontSize: '0.7rem', fontWeight: 700
                                            }}>
                                                {msg.role === 'user' ? <User size={13} /> : <Bot size={13} />}
                                            </div>

                                            {/* Message Bubble */}
                                            <div style={{
                                                padding: msg.role === 'user' ? '0.65rem 1rem' : '0.85rem 1.1rem',
                                                borderRadius: '14px',
                                                fontSize: '0.88rem', lineHeight: 1.6,
                                                background: msg.role === 'user'
                                                    ? 'linear-gradient(135deg, hsl(var(--color-secondary)), hsla(var(--color-secondary), 0.85))'
                                                    : 'hsla(var(--bg-secondary), 0.6)',
                                                color: msg.role === 'user' ? 'white' : 'hsl(var(--text-primary))',
                                                borderTopRightRadius: msg.role === 'user' ? '4px' : '14px',
                                                borderTopLeftRadius: msg.role === 'user' ? '14px' : '4px',
                                                border: msg.role === 'user' ? 'none' : '1px solid hsla(var(--border-color), 0.3)',
                                                minWidth: 0, position: 'relative'
                                            }}>
                                                {msg.role === 'assistant' ? (
                                                    <>
                                                        <div>{renderMarkdown(msg.content)}</div>
                                                        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.6rem', paddingTop: '0.4rem', borderTop: '1px solid hsla(var(--border-color), 0.2)' }}>
                                                            <CopyButton text={msg.content} />
                                                        </div>
                                                    </>
                                                ) : (
                                                    <div style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{msg.content}</div>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </>
                        )}

                        {/* Typing Indicator */}
                        {loading && (
                            <div style={{ display: 'flex', justifyContent: 'flex-start', animation: 'fadeIn 0.3s ease' }}>
                                <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'flex-start' }}>
                                    <div style={{
                                        width: '28px', height: '28px', borderRadius: '10px',
                                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                                        background: 'linear-gradient(135deg, hsl(var(--color-primary)), hsla(var(--color-primary), 0.6))',
                                        color: 'white'
                                    }}>
                                        <Bot size={13} />
                                    </div>
                                    <div style={{
                                        padding: '0.85rem 1.1rem', 
                                        background: 'hsla(var(--bg-secondary), 0.6)',
                                        border: '1px solid hsla(var(--border-color), 0.3)',
                                        borderRadius: '14px', borderTopLeftRadius: '4px',
                                        display: 'flex', gap: '0.35rem', alignItems: 'center'
                                    }}>
                                        <div style={{ display: 'flex', gap: '4px' }}>
                                            {[0, 1, 2].map(i => (
                                                <div key={i} style={{
                                                    width: '7px', height: '7px',
                                                    background: 'hsl(var(--color-primary))',
                                                    borderRadius: '50%',
                                                    animation: 'typing 1.4s infinite ease-in-out',
                                                    animationDelay: `${i * 0.15}s`,
                                                    opacity: 0.6
                                                }} />
                                            ))}
                                        </div>
                                        <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))', marginLeft: '0.4rem' }}>Thinking...</span>
                                    </div>
                                </div>
                            </div>
                        )}
                        <div ref={messagesEndRef} />
                    </div>

                    {/* ── Input Area ──────────────────────── */}
                    <form onSubmit={handleSend} style={{
                        padding: '0.85rem 1rem',
                        borderTop: '1px solid hsla(var(--border-color), 0.4)',
                        background: 'hsla(var(--bg-card), 0.8)',
                        backdropFilter: 'blur(8px)'
                    }}>
                        <div style={{ 
                            display: 'flex', gap: '0.5rem', alignItems: 'flex-end',
                            background: 'hsl(var(--bg-input))',
                            border: '1px solid hsla(var(--border-color), 0.6)',
                            borderRadius: '14px', padding: '0.3rem 0.3rem 0.3rem 0',
                            transition: 'border-color 0.2s'
                        }}>
                            <div style={{ position: 'relative', flex: 1, display: 'flex', alignItems: 'center' }}>
                                <Sparkles size={15} style={{ position: 'absolute', left: '0.85rem', color: 'hsl(var(--text-muted))', opacity: 0.5 }} />
                                <textarea
                                    ref={textareaRef}
                                    placeholder="Ask about security..."
                                    value={query}
                                    onChange={(e) => setQuery(e.target.value)}
                                    onKeyDown={handleKeyDown}
                                    rows={1}
                                    style={{
                                        width: '100%', border: 'none', background: 'transparent',
                                        color: 'hsl(var(--text-primary))',
                                        padding: '0.6rem 0.5rem 0.6rem 2.4rem',
                                        fontSize: '0.9rem', resize: 'none', outline: 'none',
                                        fontFamily: 'inherit', lineHeight: 1.5,
                                        maxHeight: '120px'
                                    }}
                                />
                            </div>
                            <button
                                type="submit"
                                disabled={!query.trim() || loading}
                                style={{
                                    width: '38px', height: '38px', padding: 0,
                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    borderRadius: '10px', flexShrink: 0, border: 'none',
                                    cursor: !query.trim() || loading ? 'not-allowed' : 'pointer',
                                    background: !query.trim() || loading 
                                        ? 'hsla(var(--text-muted), 0.15)' 
                                        : 'hsl(var(--color-primary))',
                                    color: !query.trim() || loading ? 'hsl(var(--text-muted))' : 'white',
                                    transition: 'all 0.2s',
                                    boxShadow: query.trim() && !loading ? '0 2px 8px hsla(var(--color-primary), 0.3)' : 'none'
                                }}
                            >
                                <Send size={18} />
                            </button>
                        </div>
                        <p style={{ fontSize: '0.65rem', color: 'hsl(var(--text-muted))', margin: '0.35rem 0 0 0.75rem', opacity: 0.7 }}>
                            Enter to send · Shift+Enter for new line
                        </p>
                    </form>
                </div>
            </div>

            <style>{`
                @keyframes typing {
                    0%, 100% { transform: translateY(0); opacity: 0.3; }
                    50% { transform: translateY(-4px); opacity: 1; }
                }
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(6px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                .ai-scrollbar::-webkit-scrollbar { width: 4px; }
                .ai-scrollbar::-webkit-scrollbar-track { background: transparent; }
                .ai-scrollbar::-webkit-scrollbar-thumb { background: hsla(var(--text-secondary), 0.15); border-radius: 4px; }
                .ai-scrollbar::-webkit-scrollbar-thumb:hover { background: hsla(var(--text-secondary), 0.3); }
            `}</style>
        </div>
    );
};
