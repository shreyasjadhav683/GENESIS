
import React from 'react';

import { Eye, EyeOff } from 'lucide-react';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  icon?: React.ReactNode;
  hint?: string;
}

export const Input: React.FC<InputProps> = ({ 
  label, 
  error, 
  hint,
  icon, 
  className = '', 
  type,
  ...props 
}) => {
  const [showPassword, setShowPassword] = React.useState(false);
  const isPassword = type === 'password';
  const inputType = isPassword ? (showPassword ? 'text' : 'password') : type;

  return (
    <div className="input-group">
      {label && (
        <label className="input-label">
          {label}
        </label>
      )}
      <div className="input-wrapper">
        {icon && (
          <div className="input-icon">
            {icon}
          </div>
        )}
        <input
          type={inputType}
          className={`input-field ${icon ? 'input-padding' : ''} ${error ? 'input-error' : ''} ${className}`}
          style={{ paddingRight: isPassword ? '3rem' : undefined }}
          autoComplete="off"
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="off"
          {...props}
        />
        {isPassword && (
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            style={{
              position: 'absolute',
              right: '1rem',
              top: '50%',
              transform: 'translateY(-50%)',
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              color: 'hsl(var(--text-muted))',
              padding: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'color 0.2s',
            }}
            onMouseEnter={(e) => e.currentTarget.style.color = 'hsl(var(--color-primary))'}
            onMouseLeave={(e) => e.currentTarget.style.color = 'hsl(var(--text-muted))'}
          >
            {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
          </button>
        )}
      </div>
      
      {hint && !error && (
        <span className="input-hint">{hint}</span>
      )}
      
      {error && (
        <span className="input-error-text">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          {error}
        </span>
      )}
    </div>
  );
};
