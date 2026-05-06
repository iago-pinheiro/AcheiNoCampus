import { Link } from 'react-router-dom';
import './Home.css';

export function Home() {
  // Placeholder items — will be replaced with API data
  const mockItems = [
    { id: '1', title: 'Chave encontrada perto da biblioteca', category: 'Achado', location: 'Biblioteca Central' },
    { id: '2', title: 'Mochila preta perdida no bloco B', category: 'Perdido', location: 'Bloco B' },
    { id: '3', title: 'Óculos de grau encontrados', category: 'Achado', location: 'Cantina' },
  ];

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
        <ul className="home__list" aria-label="Lista de itens recentes">
          {mockItems.map((item) => (
            <li key={item.id} className="home__list-item">
              <Link to={`/item/${item.id}`} className="item-card">
                <span className={`item-card__badge item-card__badge--${item.category.toLowerCase()}`}>
                  {item.category}
                </span>
                <h3 className="item-card__title">{item.title}</h3>
                <p className="item-card__location">📍 {item.location}</p>
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
