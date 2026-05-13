import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { User, Mail, Hash, Package, PlusCircle, LogOut } from 'lucide-react';
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

    if (user?.id) {
      fetchUserItems();
    }
  }, [user?.id]);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  if (!user) {
    return (
      <section className="profile">
        <p className="profile__error">Você precisa estar logado para ver o perfil.</p>
      </section>
    );
  }

  return (
    <section className="profile">
      <div className="profile__header">
        <div className="profile__avatar">
          <User size={40} />
        </div>
        <h1 className="profile__name">{user.name}</h1>
        <p className="profile__email">
          <Mail size={14} /> {user.email}
        </p>
        {user.ra && (
          <p className="profile__ra">
            <Hash size={14} /> RA: {user.ra}
          </p>
        )}
      </div>

      <div className="profile__stats">
        <div className="profile__stat">
          <Package size={20} />
          <span className="profile__stat-value">{items.length}</span>
          <span className="profile__stat-label">itens postados</span>
        </div>
      </div>

      <div className="profile__actions">
        <Link to="/postar" className="profile__action-btn profile__action-btn--primary">
          <PlusCircle size={18} />
          Postar novo item
        </Link>
        <button onClick={handleLogout} className="profile__action-btn profile__action-btn--danger">
          <LogOut size={18} />
          Sair da conta
        </button>
      </div>

      <div className="profile__items">
        <h2 className="profile__section-title">Meus Itens</h2>
        
        {loading && <p className="profile__status">Carregando...</p>}
        {error && <p className="profile__error">{error}</p>}
        
        {!loading && !error && items.length === 0 && (
          <div className="profile__empty">
            <Package size={48} className="profile__empty-icon" />
            <p>Você ainda não postou nenhum item.</p>
            <Link to="/postar" className="profile__empty-link">
              Postar primeiro item
            </Link>
          </div>
        )}

        {!loading && !error && items.length > 0 && (
          <div className="profile__items-grid">
            {items.map((item) => (
              <Link to={`/item/${item.id}`} key={item.id} className="profile__item-link">
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
        )}
      </div>
    </section>
  );
}