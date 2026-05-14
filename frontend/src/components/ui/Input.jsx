import { forwardRef } from 'react';
import { motion } from 'framer-motion';
import './Input.css';

export const Input = forwardRef(({
  label,
  error,
  icon,
  type = 'text',
  className = '',
  ...props
}, ref) => {
  return (
    <motion.div
      className={`input-group ${className}`}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
    >
      {label && <label className="input-label">{label}</label>}
      <div className={`input-field ${error ? 'input-field--error' : ''}`}>
        {icon && <span className="input-icon">{icon}</span>}
        <input
          ref={ref}
          type={type}
          className="input-control"
          {...props}
        />
      </div>
      {error && (
        <motion.span
          className="input-error"
          initial={{ opacity: 0, y: -4 }}
          animate={{ opacity: 1, y: 0 }}
        >
          {error}
        </motion.span>
      )}
    </motion.div>
  );
});

Input.displayName = 'Input';
