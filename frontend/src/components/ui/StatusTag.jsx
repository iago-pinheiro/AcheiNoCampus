import './StatusTag.css';

/**
 * StatusTag Component
 * Variantes: found | claimed | pending | resolved
 */
export function StatusTag({ status, className = '' }) {
  const statusMap = {
    found: { label: 'Encontrado', class: 'status-tag--found' },
    claimed: { label: 'Reivindicado', class: 'status-tag--claimed' },
    pending: { label: 'Pendente', class: 'status-tag--pending' },
    resolved: { label: 'Resolvido', class: 'status-tag--resolved' }
  };

  const current = statusMap[status] || statusMap.pending;

  return (
    <span className={`status-tag ${current.class} ${className}`}>
      {current.label}
    </span>
  );
}
