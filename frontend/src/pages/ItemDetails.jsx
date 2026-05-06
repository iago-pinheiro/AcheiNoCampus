import { useParams, Link } from 'react-router-dom';
import './ItemDetails.css';

// Placeholder data — will be replaced with GET /api/items/:id
const MOCK_ITEMS = {
  '1': {
    id: '1',
    title: 'Chave encontrada perto da biblioteca',
    category: 'Achado',
    location: 'Biblioteca Central',
    description: 'Chave simples com um pingente azul. Encontrada na mesa perto da entrada principal.',
    postedBy: 'Ana S.',
    postedAt: '2026-05-05',
  },
  '2': {
    id: '2',
    title: 'Mochila preta perdida no bloco B',
    category: 'Perdido',
    location: 'Bloco B',
    description: 'Mochila preta, marca Oakley. Contém cadernos e um carregador de notebook.',
    postedBy: 'Lucas M.',
    postedAt: '2026-05-04',
  },
};

export function ItemDetails() {
  const { id } = useParams();
  const item = MOCK_ITEMS[id];

  if (!item) {
    return (
      <section className="item-details">
        <p className="item-details__not-found">Item não encontrado.</p>
        <Link to="/" className="item-details__back">← Voltar</Link>
      </section>
    );
  }

  return (
    <section className="item-details">
      <Link to="/" className="item-details__back">← Voltar</Link>

      <div className="item-details__card">
        <span className={`item-details__badge item-details__badge--${item.category.toLowerCase()}`}>
          {item.category}
        </span>
        <h1 className="item-details__title">{item.title}</h1>

        <dl className="item-details__meta">
          <div className="item-details__meta-row">
            <dt>📍 Local</dt>
            <dd>{item.location}</dd>
          </div>
          <div className="item-details__meta-row">
            <dt>👤 Postado por</dt>
            <dd>{item.postedBy}</dd>
          </div>
          <div className="item-details__meta-row">
            <dt>📅 Data</dt>
            <dd>{item.postedAt}</dd>
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
