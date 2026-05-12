import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Search, SlidersHorizontal, Package, AlertCircle } from 'lucide-react';
import { itemsApi } from '../services/api';
import { CardItem } from '../components/ui/CardItem';
import './AllItems.css';

const FILTERS = [
  { value: '', label: 'Todos' },
  { value: 'LOST', label: 'Perdidos' },
  { value: 'FOUND', label: 'Encontrados' },
];

export function AllItems() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeFilter, setActiveFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    async function fetchItems() {
      try {
        const data = await itemsApi.getAll();
        setItems(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    fetchItems();
  }, []);

  const filteredItems = items.filter((item) => {
    const matchesStatus = !activeFilter || item.status === activeFilter;
    const matchesSearch = !searchQuery || 
      item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.location.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesStatus && matchesSearch;
  });

  return (
    <div className="all-items">
      {/* Header */}
      <div className="all-items__header">
        <h1 className="all-items__title">Todos os itens</h1>
        <p className="all-items__subtitle">
          Explore todos os itens perdidos e encontrados no campus
        </p>
      </div>

      {/* Search + Filters */}
      <div className="all-items__controls">
        <div className="all-items__search-wrapper">
          <Search size={18} className="all-items__search-icon" />
          <input
            type="text"
            className="all-items__search"
            placeholder="Buscar por título ou local..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div className="all-items__filters">
          {FILTERS.map((f) => (
            <button
              key={f.value}
              className={`all-items__filter-btn ${activeFilter === f.value ? 'all-items__filter-btn--active' : ''}`}
              onClick={() => setActiveFilter(f.value)}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {/* Content States */}
      {loading && (
        <div className="all-items__state">
          <div className="all-items__loading" />
          <p>Carregando itens...</p>
        </div>
      )}

      {error && (
        <div className="all-items__state">
          <AlertCircle size={40} className="all-items__state-icon" />
          <p>{error}</p>
          <button className="all-items__retry" onClick={() => window.location.reload()}>
            Tentar novamente
          </button>
        </div>
      )}

      {!loading && !error && filteredItems.length === 0 && (
        <div className="all-items__state">
          <Package size={40} className="all-items__state-icon" />
          <p className="all-items__state-title">Nenhum item encontrado</p>
          <p className="all-items__state-text">
            {searchQuery || activeFilter
              ? 'Tente limpar os filtros ou buscar por outro termo.'
              : 'Nenhum item foi registrado ainda.'}
          </p>
        </div>
      )}

      {!loading && !error && filteredItems.length > 0 && (
        <>
          <p className="all-items__count">
            {filteredItems.length} item{filteredItems.length !== 1 ? 'ns' : ''} encontrado{filteredItems.length !== 1 ? 's' : ''}
          </p>
          <div className="all-items__grid">
            {filteredItems.map((item) => (
              <Link to={`/item/${item.id}`} key={item.id} className="all-items__card-link">
                <CardItem 
                  title={item.title}
                  location={item.location}
                  date={new Date(item.createdAt).toLocaleDateString('pt-BR')}
                  status={item.isResolved ? 'resolved' : (item.status === 'FOUND' ? 'found' : 'pending')}
                  imageUrl={item.imageUrl}
                />
              </Link>
            ))}
          </div>
        </>
      )}
    </div>
  );
}