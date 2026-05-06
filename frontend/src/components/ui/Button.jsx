import './Button.css';

/**
 * Reusable Button Component
 * @param {string} variant - primary | secondary | success | warning
 * @param {boolean} fullWidth - Se true, o botão ocupa 100% da largura
 * @param {React.ReactNode} icon - Ícone (Lucide) opcional
 */
export function Button({
  children,
  variant = 'primary',
  fullWidth = false,
  icon,
  className = '',
  disabled,
  ...props
}) {
  const baseClass = 'btn';
  const variantClass = `btn--${variant}`;
  const widthClass = fullWidth ? 'btn--fullWidth' : '';

  return (
    <button
      className={`${baseClass} ${variantClass} ${widthClass} ${className}`.trim()}
      disabled={disabled}
      {...props}
    >
      {icon && <span className="btn__icon">{icon}</span>}
      {children}
    </button>
  );
}
