import { forwardRef } from 'react';
import './Input.css';

export const Input = forwardRef(({
  label,
  error,
  icon,
  className = '',
  ...props
}, ref) => {
  return (
    <div className={`input-wrapper ${className}`}>
      {label && <label className="input-label">{label}</label>}
      <div className={`input-container ${error ? 'input-container--error' : ''}`}>
        {icon && <span className="input-icon">{icon}</span>}
        <input 
          ref={ref}
          className="input-field" 
          {...props} 
        />
      </div>
      {error && <span className="input-error-text">{error}</span>}
    </div>
  );
});

Input.displayName = 'Input';
