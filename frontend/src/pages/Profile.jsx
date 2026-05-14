import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Package, PlusCircle, LogOut, Mail, Hash
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { itemsApi } from '../services/api';
import { CardItem } from '../components/ui/CardItem';
import './Profile.css';

export function Profile() {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function fetchUserItems() {
      try {
        const data = await itemsApi.getAll();
        const userItems = data.filter((item) => item.author?.id === user?.id);
        setItems(userItems);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    if (user?.id) fetchUserItems();
  }, [user?.id]);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  if (!user) {
    return (
      <div className="profile">
        <div className="profile__error-box">
          <p>Você precisa estar logado para ver o perfil.</p>
          <Link to="/login" className="profile__login-link">Fazer login</Link>
        </div>
      </div>
    );
  }

  const stats = [
    { label: 'Publicados', value: items.length, icon: <Package size={18} /> },
    { label: 'Resolvidos', value: items.filter(i => i.isResolved).length, icon: <Package size={18} /> },
    { label: 'Ativos', value: items.filter(i => !i.isResolved).length, icon: <Package size={18} /> },
  ];

  return (
    <motion.div
      className="profile"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      {/* Profile Header */}
      <motion.div
        className="profile__header"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <div className="profile__avatar">
          <span className="profile__avatar-letter">
            {user.name?.charAt(0)?.toUpperCase() || 'U'}
          </span>
        </div>
        <h1 className="profile__name">{user.name}</h1>
        <div className="profile__info">
          <span><Mail size={14} /> {user.email}</span>
          {user.ra && <span><Hash size={14} /> RA: {user.ra}</span>}
        </div>
      </motion.div>

      {/* Stats */}
      <motion.div
        className="profile__stats"
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1, duration: 0.3 }}
      >
        {stats.map((stat, i) => (
          <div key={i} className="profile__stat">
            <span className="profile__stat-value">{stat.value}</span>
            <span className="profile__stat-label">{stat.label}</span>
          </div>
        ))}
      </motion.div>

      {/* Actions */}
      <motion.div
        className="profile__actions"
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.15, duration: 0.3 }}
      >
        <Link to="/postar" className="profile__action-btn">
          <PlusCircle size={18} />
          Postar novo item
        </Link>
        <button onClick={handleLogout} className="profile__action-btn profile__action-btn--danger">
          <LogOut size={18} />
          Sair da conta
        </button>
      </motion.div>

      {/* Items Section */}
      <div className="profile__items">
        <h2 className="profile__section-title">Meus Itens</h2>

        {loading && (
          <div className="profile__skeleton-grid">
            {[1, 2].map((i) => (
              <div key={i} className="profile__skeleton" />
            ))}
          </div>
        )}

        {error && (
          <div className="profile__error-box">
            <p>{error}</p>
          </div>
        )}

        {!loading && !error && items.length === 0 && (
          <motion.div
            className="profile__empty"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <div className="profile__empty-icon">
              <Package size={40} />
            </div>
            <p className="profile__empty-text">Você ainda não postou nenhum item.</p>
            <Link to="/postar" className="profile__empty-link">
              Postar primeiro item
            </Link>
          </motion.div>
        )}

        {!loading && !error && items.length > 0 && (
          <motion.div
            className="profile__grid"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ staggerChildren: 0.05 }}
          >
            {items.map((item) => (
              <motion.div
                key={item.id}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
              >
                <Link to={`/item/${item.id}`} className="profile__card-link">
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
      </div>
    </motion.div>
  );
}
