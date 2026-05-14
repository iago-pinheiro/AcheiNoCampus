import { Search } from 'lucide-react';
import { motion } from 'framer-motion';
import './SearchBar.css';

export function SearchBar({
  placeholder = "Buscar itens perdidos ou encontrados...",
  onSearch,
  value,
  onChange,
  className = ''
}) {
  return (
    <motion.div
      className={`searchbar ${className}`}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: 0.1 }}
    >
      <Search className="searchbar__icon" size={20} />
      <input
        type="text"
        className="searchbar__input"
        placeholder={placeholder}
        value={value}
        onChange={onChange}
        onKeyDown={(e) => e.key === 'Enter' && onSearch?.()}
      />
      {value && (
        <motion.button
          className="searchbar__clear"
          onClick={() => onChange?.({ target: { value: '' } })}
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          whileTap={{ scale: 0.9 }}
          aria-label="Limpar busca"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <line x1="18" y1="6" x2="6" y2="18" />
            <line x1="6" y1="6" x2="18" y2="18" />
          </svg>
        </motion.button>
      )}
    </motion.div>
  );
}
