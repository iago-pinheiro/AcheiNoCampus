import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { MapPin, Tag, FileText, Image, AlertCircle, CheckCircle } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { categoriesApi, itemsApi } from '../services/api';
import './PostItem.css';

const STATUS_OPTIONS = [
  { value: 'LOST', label: 'Perdido' },
  { value: 'FOUND', label: 'Encontrado' },
];

const LOCATIONS = [
  'Biblioteca Central',
  'Bloco A',
  'Bloco B',
  'Cantina',
  'Estacionamento',
  'Laboratório',
  'Auditório',
  'Outro',
];

export function PostItem() {
  const navigate = useNavigate();
  const { token } = useAuth();

  const [categories, setCategories] = useState([]);
  const [loadingCategories, setLoadingCategories] = useState(true);
  const [categoriesError, setCategoriesError] = useState('');

  const [form, setForm] = useState({
    title: '',
    description: '',
    status: '',
    categoryId: '',
    location: '',
    imageUrl: '',
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');
  const [submitSuccess, setSubmitSuccess] = useState(false);

  useEffect(() => {
    async function fetchCategories() {
      try {
        const data = await categoriesApi.getAll();
        setCategories(data);
      } catch {
        setCategoriesError('Não foi possível carregar as categorias. Tente novamente.');
      } finally {
        setLoadingCategories(false);
      }
    }

    fetchCategories();
  }, []);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitError('');
    setSubmitSuccess(false);

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

      setTimeout(() => {
        navigate('/');
      }, 1500);
    } catch (err) {
      setSubmitError(err.message || 'Erro ao publicar o item. Tente novamente.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <section className="post-item">
      <h1 className="post-item__title">Postar item</h1>
      <p className="post-item__subtitle">
        Preencha os dados para registrar um item perdido ou encontrado.
      </p>

      {submitSuccess && (
        <div className="post-item__alert post-item__alert--success">
          <CheckCircle size={18} />
          Item publicado com sucesso! Redirecionando...
        </div>
      )}

      {submitError && (
        <div className="post-item__alert post-item__alert--error">
          <AlertCircle size={18} />
          {submitError}
        </div>
      )}

      <form
        id="post-item-form"
        className="post-item__form"
        onSubmit={handleSubmit}
        noValidate
      >
        <div className="field">
          <label htmlFor="status" className="field__label">Status do item *</label>
          <div className="field__radio-group">
            {STATUS_OPTIONS.map((option) => (
              <label key={option.value} className="field__radio-label">
                <input
                  type="radio"
                  name="status"
                  value={option.value}
                  checked={form.status === option.value}
                  onChange={handleChange}
                  className="field__radio-input"
                  required
                />
                <span className={`field__radio-chip field__radio-chip--${option.value.toLowerCase()}`}>
                  {option.label}
                </span>
              </label>
            ))}
          </div>
        </div>

        <div className="field">
          <label htmlFor="title" className="field__label">
            <Tag size={14} />
            Título do item *
          </label>
          <input
            id="title"
            name="title"
            type="text"
            className="field__input"
            placeholder="Ex: Carteira de couro marrom"
            value={form.title}
            onChange={handleChange}
            required
            disabled={isSubmitting}
          />
        </div>

        <div className="field">
          <label htmlFor="categoryId" className="field__label">
            <FileText size={14} />
            Categoria *
          </label>
          {loadingCategories ? (
            <select id="categoryId" className="field__input" disabled>
              <option value="">Carregando...</option>
            </select>
          ) : categoriesError ? (
            <select id="categoryId" className="field__input" disabled>
              <option value="">Erro ao carregar</option>
            </select>
          ) : (
            <select
              id="categoryId"
              name="categoryId"
              className="field__input"
              value={form.categoryId}
              onChange={handleChange}
              required
              disabled={isSubmitting}
            >
              <option value="" disabled>Selecione a categoria...</option>
              {categories.map((cat) => (
                <option key={cat.id} value={cat.id}>{cat.name}</option>
              ))}
            </select>
          )}
          {categoriesError && (
            <span className="field__error">{categoriesError}</span>
          )}
        </div>

        <div className="field">
          <label htmlFor="location" className="field__label">
            <MapPin size={14} />
            Local *
          </label>
          <select
            id="location"
            name="location"
            className="field__input"
            value={form.location}
            onChange={handleChange}
            required
            disabled={isSubmitting}
          >
            <option value="" disabled>Selecione o local...</option>
            {LOCATIONS.map((loc) => (
              <option key={loc} value={loc}>{loc}</option>
            ))}
          </select>
        </div>

        <div className="field">
          <label htmlFor="description" className="field__label">Descrição</label>
          <textarea
            id="description"
            name="description"
            className="field__input field__input--textarea"
            placeholder="Descreva o item com detalhes (cor, marca, características...)"
            rows={4}
            value={form.description}
            onChange={handleChange}
            disabled={isSubmitting}
          />
        </div>

        <div className="field">
          <label htmlFor="imageUrl" className="field__label">
            <Image size={14} />
            Imagem (URL)
          </label>
          <input
            id="imageUrl"
            name="imageUrl"
            type="url"
            className="field__input"
            placeholder="https://exemplo.com/foto.jpg"
            value={form.imageUrl}
            onChange={handleChange}
            disabled={isSubmitting}
          />
          <span className="field__hint">Cole o link de uma imagem do item (opcional)</span>
        </div>

        <button
          id="submit-post-item"
          type="submit"
          className="post-item__submit"
          disabled={isSubmitting || loadingCategories}
        >
          {isSubmitting ? 'Publicando...' : 'Publicar item'}
        </button>
      </form>
    </section>
  );
}