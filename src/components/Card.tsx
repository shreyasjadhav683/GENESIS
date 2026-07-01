
import React from 'react';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
  title?: string;
  description?: string;
  onClick?: () => void;
  style?: React.CSSProperties;
  bodyStyle?: React.CSSProperties;
  variant?: 'default' | 'glass' | 'gradient';
  noPadding?: boolean;
}

export const Card: React.FC<CardProps> = ({ 
  children, 
  className = '', 
  bodyClassName = '', 
  title, 
  description, 
  onClick, 
  style,
  bodyStyle,
  variant = 'default',
  noPadding = false
}) => {
  const variantClasses = {
    default: '',
    glass: 'glass',
    gradient: 'gradient-border'
  };

  return (
    <div 
      onClick={onClick}
      className={`card ${variantClasses[variant]} ${onClick ? 'card-hover' : ''} ${className}`}
      style={{
        ...style,
        ...(noPadding ? { padding: 0 } : {})
      }}
    >
      {(title || description) && (
        <div className="card-header">
          {title && <h3 className="card-title">{title}</h3>}
          {description && <p className="card-desc">{description}</p>}
        </div>
      )}
      <div className={`card-body ${bodyClassName}`} style={{
        ...(noPadding ? { padding: 0 } : {}),
        ...bodyStyle
      }}>
        {children}
      </div>
    </div>
  );
};
