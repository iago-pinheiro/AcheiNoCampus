import { useState, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Package, AlertCircle } from 'lucide-react';
import { itemsApi } from '../services/api';
import { CardItem } from '../components/ui/CardItem';
import { SearchBar } from '../components/ui/SearchBar';
import './AllItems.css';

const FILTERS = [
  { value: '', label: 'Todos' },
  { value: 'LOST', label: 'Perdidos' },
  { value: 'FOUND', label: 'Encontrados' },
];

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.04 }
  }
};

const itemVariants = {
  hidden: { opacity: 0, y: 16 },
  visible: { opacity: 1, y: 0 }
};

export function AllItems() {
  const [searchParams] = useSearchParams();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeFilter, setActiveFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState(searchParams.get('q') || '');

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
    const q = searchQuery.toLowerCase();
    const matchesSearch = !q ||
      item.title.toLowerCase().includes(q) ||
      (item.location && item.location.toLowerCase().includes(q)) ||
      (item.description && item.description.toLowerCase().includes(q));
    return matchesStatus && matchesSearch;
  });

  return (
    <motion.div
      className="explore"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      <div className="explore__header">
        <h1 className="explore__title">Explorar Itens</h1>
        <p className="explore__subtitle">
          {filteredItems.length} item{filteredItems.length !== 1 ? 'ns' : ''} encontrado{filteredItems.length !== 1 ? 's' : ''}
        </p>
      </div>

      <div className="explore__controls">
        <SearchBar
          placeholder="Buscar por título, local ou descrição..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />

        <div className="explore__filters">
          {FILTERS.map((f) => (
            <motion.button
              key={f.value}
              className={`explore__filter-btn ${activeFilter === f.value ? 'explore__filter-btn--active' : ''}`}
              onClick={() => setActiveFilter(f.value)}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.97 }}
            >
              {f.label}
            </motion.button>
          ))}
        </div>
      </div>

      {loading && (
        <div className="explore__state">
          <div className="explore__skeleton-grid">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="explore__skeleton" />
            ))}
          </div>
        </div>
      )}

      {error && (
        <motion.div
          className="explore__state"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <div className="explore__state-box">
            <AlertCircle size={40} className="explore__state-icon" />
            <p className="explore__state-title">Erro ao carregar</p>
            <p className="explore__state-text">{error}</p>
            <button className="explore__retry" onClick={() => window.location.reload()}>
              Tentar novamente
            </button>
          </div>
        </motion.div>
      )}

      {!loading && !error && filteredItems.length === 0 && (
        <motion.div
          className="explore__state"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <div className="explore__state-box">
            <Package size={40} className="explore__state-icon" />
            <p className="explore__state-title">Nenhum item encontrado</p>
            <p className="explore__state-text">
              {searchQuery || activeFilter
                ? 'Tente limpar os filtros ou buscar por outro termo.'
                : 'Nenhum item foi registrado ainda.'}
            </p>
          </div>
        </motion.div>
      )}

      {!loading && !error && filteredItems.length > 0 && (
        <motion.div
          className="explore__grid"
          variants={containerVariants}
          initial="hidden"
          animate="visible"
        >
          {filteredItems.map((item) => (
            <motion.div key={item.id} variants={itemVariants}>
              <Link to={`/item/${item.id}`} className="explore__card-link">
                <CardItem
                  title={item.title}
                  location={item.location}
                  date={new Date(item.createdAt).toLocaleDateString('pt-BR')}
                  status={item.isResolved ? 'resolved' : (item.status === 'FOUND' ? 'found' : 'pending')}
                  imageUrl={item.imageUrl}
                />
              </Link>
            </motion.div>
          ))}
        </motion.div>
      )}
    </motion.div>
  );
}
