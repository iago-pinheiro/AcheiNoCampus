import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  MapPin, Tag, FileText, Image, AlertCircle,
  CheckCircle, ChevronLeft
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { itemsApi } from '../services/api';
import { Button } from '../components/ui/Button';
import './PostItem.css';

const STATUS_OPTIONS = [
  { value: 'LOST', label: 'Perdido', desc: 'Você perdeu este item' },
  { value: 'FOUND', label: 'Encontrado', desc: 'Você encontrou este item' },
];

const LOCATIONS = [
  'Biblioteca Central',
  'Bloco A',
  'Bloco B',
  'Bloco C',
  'Cantina',
  'Estacionamento',
  'Laboratório',
  'Auditório',
  'Restaurante Universitário',
  'Área Esportiva',
  'Outro',
];

const CATEGORIES = [
  { id: 'eletronicos', name: 'Eletrônicos' },
  { id: 'acessorios', name: 'Acessórios' },
  { id: 'documentos', name: 'Documentos' },
  { id: 'chaves', name: 'Chaves' },
  { id: 'roupas', name: 'Roupas' },
  { id: 'livros', name: 'Livros/Materiais' },
  { id: 'pessoais', name: 'Objetos Pessoais' },
  { id: 'outros', name: 'Outros' },
];

export function PostItem() {
  const navigate = useNavigate();
  const { token } = useAuth();

  const [form, setForm] = useState({
    title: '',
    description: '',
    status: '',
    categoryId: '',
    location: '',
    imageUrl: '',
  });

  const [step, setStep] = useState(1);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');
  const [submitSuccess, setSubmitSuccess] = useState(false);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitError('');

    if (!form.title || !form.status || !form.categoryId || !form.location) {
      setSubmitError('Preencha todos os campos obrigatórios.');
      return;
    }
    if (!token) {
      setSubmitError('Você precisa estar logado para postar um item.');
      return;
    }

    setIsSubmitting(true);
    try {
      await itemsApi.create({
        title: form.title,
        description: form.description || '',
        status: form.status,
        categoryId: form.categoryId,
        location: form.location,
        imageUrl: form.imageUrl || null,
      });
      setSubmitSuccess(true);
      setTimeout(() => navigate('/'), 1500);
    } catch (err) {
      setSubmitError(err.message || 'Erro ao publicar o item. Tente novamente.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <motion.div
      className="post"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      <div className="post__header">
        {step > 1 ? (
          <button type="button" className="post__back" onClick={() => setStep(step - 1)}>
            <ChevronLeft size={22} />
          </button>
        ) : (
          <div />
        )}
        <div className="post__steps">
          <span className={`post__step-dot ${step >= 1 ? 'post__step-dot--active' : ''}`} />
          <span className={`post__step-line ${step >= 2 ? 'post__step-line--active' : ''}`} />
          <span className={`post__step-dot ${step >= 2 ? 'post__step-dot--active' : ''}`} />
        </div>
        <div />
      </div>

      <h1 className="post__title">Publicar Item</h1>
      <p className="post__subtitle">
        {step === 1 ? 'Primeiro, conte o que aconteceu' : 'Agora, descreva o item'}
      </p>

      {submitSuccess && (
        <motion.div
          className="post__alert post__alert--success"
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <CheckCircle size={18} />
          Item publicado com sucesso!
        </motion.div>
      )}

      {submitError && (
        <motion.div
          className="post__alert post__alert--error"
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <AlertCircle size={18} />
          {submitError}
        </motion.div>
      )}

      <form className="post__form" onSubmit={handleSubmit} noValidate>
        {step === 1 && (
          <motion.div
            className="post__step-content"
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.2 }}
          >
            <div className="post__field">
              <label className="post__label">O que aconteceu? *</label>
              <div className="post__status-group">
                {STATUS_OPTIONS.map((option) => (
                  <label
                    key={option.value}
                    className={`post__status-chip ${form.status === option.value ? `post__status-chip--${option.value.toLowerCase()}` : ''}`}
                  >
                    <input
                      type="radio"
                      name="status"
                      value={option.value}
                      checked={form.status === option.value}
                      onChange={handleChange}
                      className="sr-only"
                    />
                    <span className="post__status-emoji">
                      {option.value === 'LOST' ? '😔' : '🙌'}
                    </span>
                    <div className="post__status-info">
                      <strong>{option.label}</strong>
                      <span>{option.desc}</span>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <div className="post__field">
              <label className="post__label" htmlFor="location">Onde? *</label>
              <div className="post__select-wrap">
                <MapPin size={18} className="post__select-icon" />
                <select
                  id="location"
                  name="location"
                  className="post__select"
                  value={form.location}
                  onChange={handleChange}
                  required
                >
                  <option value="" disabled>Selecione o local...</option>
                  {LOCATIONS.map((loc) => (
                    <option key={loc} value={loc}>{loc}</option>
                  ))}
                </select>
              </div>
            </div>

            <Button
              type="button"
              variant="primary"
              size="lg"
              fullWidth
              onClick={() => setStep(2)}
              disabled={!form.status || !form.location}
            >
              Continuar
            </Button>
          </motion.div>
        )}

        {step === 2 && (
          <motion.div
            className="post__step-content"
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.2 }}
          >
            <div className="post__field">
              <label className="post__label" htmlFor="title">Título do item *</label>
              <div className="post__input-wrap">
                <Tag size={18} className="post__input-icon" />
                <input
                  id="title"
                  name="title"
                  type="text"
                  className="post__input"
                  placeholder="Ex: Carteira de couro marrom"
                  value={form.title}
                  onChange={handleChange}
                  required
                />
              </div>
            </div>

            <div className="post__field">
              <label className="post__label" htmlFor="categoryId">Categoria *</label>
              <div className="post__select-wrap">
                <FileText size={18} className="post__select-icon" />
                <select
                  id="categoryId"
                  name="categoryId"
                  className="post__select"
                  value={form.categoryId}
                  onChange={handleChange}
                  required
                >
                  <option value="" disabled>Selecione a categoria...</option>
                  {CATEGORIES.map((cat) => (
                    <option key={cat.id} value={cat.id}>{cat.name}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="post__field">
              <label className="post__label" htmlFor="description">Descrição</label>
              <textarea
                id="description"
                name="description"
                className="post__textarea"
                placeholder="Descreva o item com detalhes (cor, marca, características...)"
                rows={3}
                value={form.description}
                onChange={handleChange}
              />
            </div>

            <div className="post__field">
              <label className="post__label" htmlFor="imageUrl">Imagem (URL)</label>
              <div className="post__input-wrap">
                <Image size={18} className="post__input-icon" />
                <input
                  id="imageUrl"
                  name="imageUrl"
                  type="url"
                  className="post__input"
                  placeholder="https://exemplo.com/foto.jpg"
                  value={form.imageUrl}
                  onChange={handleChange}
                />
              </div>
              <span className="post__hint">Cole o link de uma imagem do item (opcional)</span>
            </div>

            <div className="post__actions">
              <Button
                type="submit"
                variant="primary"
                size="lg"
                fullWidth
                disabled={isSubmitting || !form.title || !form.categoryId}
              >
                {isSubmitting ? 'Publicando...' : 'Publicar item'}
              </Button>
            </div>
          </motion.div>
        )}
      </form>
    </motion.div>
  );
}
