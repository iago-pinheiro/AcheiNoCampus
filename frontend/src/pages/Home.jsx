import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Search, PlusCircle, Shield, Clock, Users, ArrowRight, CheckCircle } from 'lucide-react';
import { itemsApi } from '../services/api';
import { CardItem } from '../components/ui/CardItem';
import logoSideText from '../assets/logo_side_text_nav.png';
import './Home.css';

export function Home() {
  const navigate = useNavigate();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    async function fetchItems() {
      try {
        const data = await itemsApi.getAll();
        setItems(data.slice(0, 6));
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    fetchItems();
  }, []);

  const recentItems = items.slice(0, 4);

  return (
    <div className="home">
      {/* Hero Section */}
      <section className="home__hero">
        <div className="home__hero-content">
          <h1 className="home__title">
            Encontre seus objetos <span className="home__title-highlight">perdidos no campus</span>
          </h1>
          
          <p className="home__subtitle">
            Conectamos estudantes que perderam itens com quem encontrou. 
            Rápido, simples e seguro.
          </p>
          
          <div className="home__hero-cta">
            <Link to="/postar" className="home__hero-btn home__hero-btn--primary">
              <PlusCircle size={20} />
              Postar Item
            </Link>
            <Link to="/login" className="home__hero-btn home__hero-btn--secondary">
              Entrar
            </Link>
          </div>
          
          <div className="home__trust">
            <CheckCircle size={16} />
            <span>+500 itens recuperados este semestre</span>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="home__features">
        <div className="home__features-grid">
          <div className="home__feature">
            <div className="home__feature-icon">
              <Clock size={22} />
            </div>
            <div className="home__feature-content">
              <h3>Rápido</h3>
              <p>Postando em menos de 1 minuto</p>
            </div>
          </div>
          
          <div className="home__feature">
            <div className="home__feature-icon">
              <Shield size={22} />
            </div>
            <div className="home__feature-content">
              <h3>Seguro</h3>
              <p>Autenticação para proteger seus dados</p>
            </div>
          </div>
          
          <div className="home__feature">
            <div className="home__feature-icon">
              <Users size={22} />
            </div>
            <div className="home__feature-content">
              <h3>Comunidade</h3>
              <p>Conectamos toda a comunidade acadêmica</p>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="home__how-it-works">
        <h2 className="home__section-title">Como funciona</h2>
        
        <div className="home__steps">
          <div className="home__step">
            <span className="home__step-number">1</span>
            <div className="home__step-content">
              <h3>Perdeu um item?</h3>
              <p>Post rapidement avec les détails</p>
            </div>
          </div>
          
          <div className="home__step">
            <span className="home__step-number">2</span>
            <div className="home__step-content">
              <h3>Encontrou algo?</h3>
              <p>Registre e aguarde o dono</p>
            </div>
          </div>
          
          <div className="home__step">
            <span className="home__step-number">3</span>
            <div className="home__step-content">
              <h3>Reunião</h3>
              <p>Combine a retirada no campus</p>
            </div>
          </div>
        </div>
      </section>

      {/* Recent Items (Optional - collapsible) */}
      {recentItems.length > 0 && (
        <section className="home__feed">
          <h2 className="home__section-title">Itens recentes</h2>
          
          <div className="home__grid">
            {recentItems.map((item) => (
              <Link to={`/item/${item.id}`} key={item.id} className="home__card-link">
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
          
          <Link to="/login" className="home__see-all">
            Ver todos os itens <ArrowRight size={16} />
          </Link>
        </section>
      )}

      {/* Final CTA */}
      <section className="home__cta">
        <div className="home__cta-content">
          <h2>Comece agora mesmo</h2>
          <p>Junte-se à comunidade e ajude a encontrar objetos perdidos</p>
          <Link to="/cadastro" className="home__cta-btn">
            Criar conta grátis
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="home__footer">
        <div className="home__footer-logo">
          <img src={logoSideText} alt="Achei no Campus" />
        </div>
        <p className="home__footer-text">© 2026 Achei no Campus. Todos os direitos reservados.</p>
      </footer>
    </div>
  );
}