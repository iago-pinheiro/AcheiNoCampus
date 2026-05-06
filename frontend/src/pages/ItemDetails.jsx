import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import './ItemDetails.css';

export function ItemDetails() {
  const { id } = useParams();
  const [item, setItem] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function fetchItem() {
      try {
        const response = await fetch(`http://localhost:3000/api/items/${id}`);
        if (!response.ok) {
          if (response.status === 404) {
            throw new Error('Item não encontrado.');
          }
          throw new Error('Falha ao carregar o item.');
        }
        const data = await response.json();
        setItem(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    fetchItem();
  }, [id]);

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
        <span className={`item-details__badge item-details__badge--${item.status.toLowerCase()}`}>
          {item.status === 'FOUND' ? 'Achado' : 'Perdido'}
        </span>
        <h1 className="item-details__title">{item.title}</h1>

        <dl className="item-details__meta">
          <div className="item-details__meta-row">
            <dt>📍 Local</dt>
            <dd>{item.location}</dd>
          </div>
          {item.category && (
            <div className="item-details__meta-row">
              <dt>🏷️ Categoria</dt>
              <dd>{item.category.name}</dd>
            </div>
          )}
          {item.author && (
            <div className="item-details__meta-row">
              <dt>👤 Postado por</dt>
              <dd>{item.author.name}</dd>
            </div>
          )}
          <div className="item-details__meta-row">
            <dt>📅 Data</dt>
            <dd>{new Date(item.createdAt).toLocaleDateString('pt-BR')}</dd>
          </div>
        </dl>

        <p className="item-details__description">{item.description}</p>

        <button id="contact-owner-btn" className="item-details__contact">
          Entrar em contato
        </button>
      </div>
    </section>
  );
}
