import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import './Home.css';

export function Home() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function fetchItems() {
      try {
        const response = await fetch('http://localhost:3000/api/items');
        if (!response.ok) {
          throw new Error('Falha ao carregar os itens');
        }
        const data = await response.json();
        setItems(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    fetchItems();
  }, []);

  return (
    <section className="home">
      <div className="home__hero">
        <h1 className="home__title">Itens perdidos e achados no campus</h1>
        <p className="home__subtitle">Encontre ou registre itens perdidos na sua universidade.</p>
        <Link to="/postar" className="home__cta">
          Postar item
        </Link>
      </div>

      <div className="home__feed">
        <h2 className="home__section-title">Publicações recentes</h2>
        
        {loading && <p>Carregando itens...</p>}
        {error && <p className="error-message">{error}</p>}
        
        {!loading && !error && items.length === 0 && (
          <p>Nenhum item encontrado no momento.</p>
        )}

        {!loading && !error && items.length > 0 && (
          <ul className="home__list" aria-label="Lista de itens recentes">
            {items.map((item) => (
              <li key={item.id} className="home__list-item">
                <Link to={`/item/${item.id}`} className="item-card">
                  <span className={`item-card__badge item-card__badge--${item.status.toLowerCase()}`}>
                    {item.status === 'FOUND' ? 'Achado' : 'Perdido'}
                  </span>
                  <h3 className="item-card__title">{item.title}</h3>
                  <p className="item-card__location">📍 {item.location}</p>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
