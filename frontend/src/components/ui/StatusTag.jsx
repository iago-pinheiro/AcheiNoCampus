import { motion } from 'framer-motion';
import './StatusTag.css';

export function StatusTag({ status, className = '' }) {
  const statusMap = {
    found: { label: 'Encontrado', class: 'tag--found' },
    claimed: { label: 'Reivindicado', class: 'tag--claimed' },
    pending: { label: 'Pendente', class: 'tag--pending' },
    resolved: { label: 'Resolvido', class: 'tag--resolved' }
  };

  const current = statusMap[status] || statusMap.pending;

  return (
    <motion.span
      className={`tag ${current.class} ${className}`}
      initial={{ opacity: 0, scale: 0.8 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.15 }}
    >
      {current.label}
    </motion.span>
  );
}
