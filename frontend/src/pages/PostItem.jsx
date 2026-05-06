import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './PostItem.css';

const CATEGORIES = ['Achado', 'Perdido'];
const LOCATIONS = ['Biblioteca Central', 'Bloco A', 'Bloco B', 'Cantina', 'Estacionamento', 'Outro'];

export function PostItem() {
  const navigate = useNavigate();

  const [form, setForm] = useState({
    title: '',
    description: '',
    category: '',
    location: '',
  });

  function handleChange(e) {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  }

  function handleSubmit(e) {
    e.preventDefault();
    // TODO: integrate with POST /api/items
    console.log('Submitting:', form);
    navigate('/');
  }

  return (
    <section className="post-item">
      <h1 className="post-item__title">Postar item</h1>
      <p className="post-item__subtitle">Preencha os dados do item encontrado ou perdido.</p>

      <form id="post-item-form" className="post-item__form" onSubmit={handleSubmit} noValidate>
        <div className="field">
          <label htmlFor="title" className="field__label">Título</label>
          <input
            id="title"
            name="title"
            type="text"
            className="field__input"
            placeholder="Ex: Chave com pingente azul"
            value={form.title}
            onChange={handleChange}
            required
          />
        </div>

        <div className="field">
          <label htmlFor="category" className="field__label">Categoria</label>
          <select
            id="category"
            name="category"
            className="field__input"
            value={form.category}
            onChange={handleChange}
            required
          >
            <option value="" disabled>Selecione...</option>
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        </div>

        <div className="field">
          <label htmlFor="location" className="field__label">Local</label>
          <select
            id="location"
            name="location"
            className="field__input"
            value={form.location}
            onChange={handleChange}
            required
          >
            <option value="" disabled>Selecione...</option>
            {LOCATIONS.map((l) => (
              <option key={l} value={l}>{l}</option>
            ))}
          </select>
        </div>

        <div className="field">
          <label htmlFor="description" className="field__label">Descrição</label>
          <textarea
            id="description"
            name="description"
            className="field__input field__input--textarea"
            placeholder="Descreva o item com detalhes..."
            rows={4}
            value={form.description}
            onChange={handleChange}
          />
        </div>

        <button id="submit-post-item" type="submit" className="post-item__submit">
          Publicar
        </button>
      </form>
    </section>
  );
}
