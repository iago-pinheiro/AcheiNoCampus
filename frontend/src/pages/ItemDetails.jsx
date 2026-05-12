import { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { MapPin, Tag, User, Calendar, CheckCircle, Mail } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { StatusTag } from '../components/ui/StatusTag';
import { itemsApi } from '../services/api';
import './ItemDetails.css';

export function ItemDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user, token } = useAuth();
  const [item, setItem] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [resolving, setResolving] = useState(false);

  useEffect(() => {
    async function fetchItem() {
      try {
        const data = await itemsApi.getById(id);
        setItem(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    fetchItem();
  }, [id]);

  const handleResolve = async () => {
    if (!token) {
      navigate('/login');
      return;
    }

    setResolving(true);
    try {
      await itemsApi.resolve(id);
      setItem((prev) => ({ ...prev, isResolved: true }));
    } catch (err) {
      alert(err.message || 'Erro ao marcar item como resolvido.');
    } finally {
      setResolving(false);
    }
  };

  const isAuthor = user && item && item.author && item.author.id === user.id;

  const getStatusTag = () => {
    if (item.isResolved) return 'resolved';
    return item.status === 'FOUND' ? 'found' : 'pending';
  };

  const handleContact = () => {
    if (!token) {
      navigate('/login');
      return;
    }
    if (item.author?.email) {
      window.location.href = `mailto:${item.author.email}?subject=Item: ${item.title}`;
    }
  };

  if (loading) {
    return (
      <section className="item-details">
        <Link to="/" className="item-details__back">← Voltar</Link>
        <p>Carregando detalhes...</p>
      </section>
    );
  }

  if (error || !item) {
    return (
      <section className="item-details">
        <p className="item-details__not-found">{error || 'Item não encontrado.'}</p>
        <Link to="/" className="item-details__back">← Voltar</Link>
      </section>
    );
  }

  return (
    <section className="item-details">
      <Link to="/" className="item-details__back">← Voltar</Link>

      <div className="item-details__card">
        <StatusTag status={getStatusTag()} />
        <h1 className="item-details__title">{item.title}</h1>

        <dl className="item-details__meta">
          <div className="item-details__meta-row">
            <dt><MapPin size={16} className="item-details__icon" /> Local</dt>
            <dd>{item.location}</dd>
          </div>
          {item.category && (
            <div className="item-details__meta-row">
              <dt><Tag size={16} className="item-details__icon" /> Categoria</dt>
              <dd>{item.category.name}</dd>
            </div>
          )}
          {item.author && (
            <div className="item-details__meta-row">
              <dt><User size={16} className="item-details__icon" /> Postado por</dt>
              <dd>{item.author.name}</dd>
            </div>
          )}
          <div className="item-details__meta-row">
            <dt><Calendar size={16} className="item-details__icon" /> Data</dt>
            <dd>{new Date(item.createdAt).toLocaleDateString('pt-BR')}</dd>
          </div>
        </dl>

        <p className="item-details__description">{item.description}</p>

        <div className="item-details__actions">
          {!isAuthor && !item.isResolved && (
            <button 
              id="contact-owner-btn" 
              className="item-details__contact"
              onClick={handleContact}
            >
              <Mail size={18} />
              Entrar em contato
            </button>
          )}

          {isAuthor && !item.isResolved && (
            <button 
              className="item-details__resolve"
              onClick={handleResolve}
              disabled={resolving}
            >
              <CheckCircle size={18} />
              {resolving ? 'Marcando...' : 'Marcar como resolvido'}
            </button>
          )}

          {item.isResolved && (
            <div className="item-details__resolved-notice">
              <CheckCircle size={18} />
              Este item foi resolvido
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
