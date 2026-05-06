import { Search, Plus } from 'lucide-react';
import './SearchBar.css';

/**
 * SearchBar Component
 * Baseada no brand board com sombra leve, input oval e botão de ação
 */
export function SearchBar({
  placeholder = "Find your lost item...",
  onSearch,
  onAddClick,
  value,
  onChange,
  className = ''
}) {
  return (
    <div className={`search-bar ${className}`}>
      <Search className="search-bar__icon" size={20} />
      <input 
        type="text" 
        className="search-bar__input" 
        placeholder={placeholder}
        value={value}
        onChange={onChange}
        onKeyDown={(e) => e.key === 'Enter' && onSearch?.()}
      />
      {onAddClick && (
        <button 
          className="search-bar__action" 
          onClick={onAddClick}
          aria-label="Adicionar item"
        >
          <Plus size={18} />
        </button>
      )}
    </div>
  );
}
