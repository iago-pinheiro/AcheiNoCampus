import { motion } from 'framer-motion';
import './Button.css';

export function Button({
  children,
  variant = 'primary',
  size = 'md',
  fullWidth = false,
  icon,
  className = '',
  disabled,
  ...props
}) {
  const classes = [
    'btn',
    `btn--${variant}`,
    `btn--${size}`,
    fullWidth ? 'btn--full' : '',
    className
  ].filter(Boolean).join(' ');

  return (
    <motion.button
      className={classes}
      disabled={disabled}
      whileHover={disabled ? {} : { scale: 1.02 }}
      whileTap={disabled ? {} : { scale: 0.98 }}
      {...props}
    >
      {icon && <span className="btn__icon">{icon}</span>}
      {children}
    </motion.button>
  );
}
