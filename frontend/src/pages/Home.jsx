import { useState, useEffect, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Laptop, Key, BookOpen, Shirt, Smartphone,
  Wallet, Watch, Headphones, Bot, ArrowRight
} from 'lucide-react';
import { itemsApi } from '../services/api';
import { CardItem } from '../components/ui/CardItem';
import { SearchBar } from '../components/ui/SearchBar';
import './Home.css';

const CATEGORIES = [
  { id: 'eletronicos', label: 'Eletrônicos', icon: <Laptop size={22} /> },
  { id: 'chaves', label: 'Chaves', icon: <Key size={22} /> },
  { id: 'livros', label: 'Livros', icon: <BookOpen size={22} /> },
  { id: 'roupas', label: 'Roupas', icon: <Shirt size={22} /> },
  { id: 'celulares', label: 'Celulares', icon: <Smartphone size={22} /> },
  { id: 'carteiras', label: 'Carteiras', icon: <Wallet size={22} /> },
  { id: 'relogios', label: 'Relógios', icon: <Watch size={22} /> },
  { id: 'fones', label: 'Fones', icon: <Headphones size={22} /> },
  { id: 'outros', label: 'Outros', icon: <Bot size={22} /> },
];

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.05 }
  }
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0 }
};

export function Home() {
  const navigate = useNavigate();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeCategory, setActiveCategory] = useState(null);
  const scrollRef = useRef(null);

  useEffect(() => {
    async function fetchItems() {
      try {
        const data = await itemsApi.getAll();
        setItems(data);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    fetchItems();
  }, []);

  const recentItems = items.slice(0, 6);

  return (
    <div className="home">
      {/* Header Section */}
      <motion.section
        className="home__hero"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <div className="home__hero-badge">
          <span className="home__hero-dot" />
          Comunidade Universitária
        </div>
        <h1 className="home__title">
          Achou algo no campus?
        </h1>
        <p className="home__subtitle">
          Conectamos quem perdeu com quem encontrou. Rápido, fácil e seguro.
        </p>
      </motion.section>

      {/* Search */}
      <div className="home__search">
        <SearchBar
          placeholder="Buscar itens perdidos ou encontrados..."
          value={searchQuery}
          onChange={(e) => {
            setSearchQuery(e.target.value);
            if (e.target.value.length > 2) {
              navigate(`/itens?q=${encodeURIComponent(e.target.value)}`);
            }
          }}
        />
      </div>

      {/* Categories */}
      <motion.section
        className="home__categories"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.15, duration: 0.3 }}
      >
        <div className="home__categories-header">
          <h2 className="home__section-title">Categorias</h2>
        </div>
        <div className="home__categories-scroll" ref={scrollRef}>
          {CATEGORIES.map((cat, i) => (
            <motion.button
              key={cat.id}
              className={`home__category-chip ${activeCategory === cat.id ? 'home__category-chip--active' : ''}`}
              onClick={() => {
                setActiveCategory(activeCategory === cat.id ? null : cat.id);
                navigate(`/itens?categoria=${cat.id}`);
              }}
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 + i * 0.03 }}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <span className="home__category-icon">{cat.icon}</span>
              <span className="home__category-label">{cat.label}</span>
            </motion.button>
          ))}
        </div>
      </motion.section>

      {/* Feed */}
      <motion.section
        className="home__feed"
        variants={containerVariants}
        initial="hidden"
        animate="visible"
      >
        <div className="home__feed-header">
          <h2 className="home__section-title">Itens Recentes</h2>
          <Link to="/itens" className="home__see-all">
            Ver todos
            <ArrowRight size={16} />
          </Link>
        </div>

        {loading ? (
          <div className="home__skeleton-grid">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="home__skeleton" />
            ))}
          </div>
        ) : recentItems.length > 0 ? (
          <motion.div className="home__grid" variants={containerVariants}>
            {recentItems.map((item) => (
              <motion.div key={item.id} variants={itemVariants}>
                <Link to={`/item/${item.id}`} className="home__card-link">
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
        ) : (
          <motion.div
            className="home__empty"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <div className="home__empty-icon">
              <Bot size={48} />
            </div>
            <p className="home__empty-title">Nenhum item registrado ainda</p>
            <p className="home__empty-text">Seja o primeiro a postar um item encontrado ou perdido!</p>
          </motion.div>
        )}
      </motion.section>
    </div>
  );
}
