import { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  MapPin, Tag, User, Calendar, CheckCircle,
  Mail, ChevronLeft, Image as ImageIcon, Shield
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { StatusTag } from '../components/ui/StatusTag';
import { Button } from '../components/ui/Button';
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
    if (!token) { navigate('/login'); return; }
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
    if (!token) { navigate('/login'); return; }
    if (item.author?.email) {
      window.location.href = `mailto:${item.author.email}?subject=Item: ${item.title}`;
    }
  };

  if (loading) {
    return (
      <div className="detail">
        <div className="detail__loading">
          <div className="detail__skeleton detail__skeleton--image" />
          <div className="detail__skeleton detail__skeleton--title" />
          <div className="detail__skeleton detail__skeleton--text" />
          <div className="detail__skeleton detail__skeleton--text" />
          <div className="detail__skeleton detail__skeleton--text" />
        </div>
      </div>
    );
  }

  if (error || !item) {
    return (
      <div className="detail">
        <div className="detail__error">
          <p>{error || 'Item não encontrado.'}</p>
          <Link to="/" className="detail__back-btn">Voltar ao início</Link>
        </div>
      </div>
    );
  }

  return (
    <motion.div
      className="detail"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      {/* Back button */}
      <Link to="/" className="detail__back">
        <ChevronLeft size={22} />
        Voltar
      </Link>

      {/* Image */}
      <motion.div
        className="detail__image-wrap"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        {item.imageUrl ? (
          <img src={item.imageUrl} alt={item.title} className="detail__image" />
        ) : (
          <div className="detail__image-placeholder">
            <ImageIcon size={48} />
          </div>
        )}
        <div className="detail__image-status">
          <StatusTag status={getStatusTag()} />
        </div>
      </motion.div>

      {/* Content */}
      <motion.div
        className="detail__content"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.1 }}
      >
        <h1 className="detail__title">{item.title}</h1>

        <div className="detail__meta">
          {item.location && (
            <div className="detail__meta-row">
              <MapPin size={16} />
              <span>{item.location}</span>
            </div>
          )}
          {item.category && (
            <div className="detail__meta-row">
              <Tag size={16} />
              <span>{item.category.name}</span>
            </div>
          )}
          {item.author && (
            <div className="detail__meta-row">
              <User size={16} />
              <span>Postado por {item.author.name}</span>
            </div>
          )}
          <div className="detail__meta-row">
            <Calendar size={16} />
            <span>{new Date(item.createdAt).toLocaleDateString('pt-BR')}</span>
          </div>
        </div>

        {item.description && (
          <div className="detail__description">
            <h3>Descrição</h3>
            <p>{item.description}</p>
          </div>
        )}

        <div className="detail__actions">
          {!isAuthor && !item.isResolved && (
            <Button
              variant="warning"
              size="lg"
              fullWidth
              icon={<Mail size={20} />}
              onClick={handleContact}
            >
              Esse item é meu
            </Button>
          )}

          {isAuthor && !item.isResolved && (
            <Button
              variant="success"
              size="lg"
              fullWidth
              icon={<CheckCircle size={20} />}
              onClick={handleResolve}
              disabled={resolving}
            >
              {resolving ? 'Marcando...' : 'Marcar como resolvido'}
            </Button>
          )}

          {item.isResolved && (
            <div className="detail__resolved">
              <CheckCircle size={20} />
              <span>Este item foi resolvido</span>
            </div>
          )}

          <div className="detail__trust">
            <Shield size={14} />
            <span>Encontro presencial seguro no campus</span>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}
