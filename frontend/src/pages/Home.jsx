import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { PlusCircle, Clock, Shield, Users, ArrowRight, Eye } from 'lucide-react';
import { itemsApi } from '../services/api';
import { CardItem } from '../components/ui/CardItem';
import './Home.css';

export function Home() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchItems() {
      try {
        const data = await itemsApi.getAll();
        setItems(data);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    fetchItems();
  }, []);

  const recentItems = items.slice(0, 4);
  const hasMoreItems = items.length > 4;

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
        </div>
      </section>

      {/* Features */}
      <section className="home__features">
        <div className="home__features-grid">
          <div className="home__feature">
            <div className="home__feature-icon">
              <Clock size={20} />
            </div>
            <div className="home__feature-content">
              <h3>Rápido</h3>
              <p>Postando em menos de 1 minuto</p>
            </div>
          </div>
          
          <div className="home__feature">
            <div className="home__feature-icon">
              <Shield size={20} />
            </div>
            <div className="home__feature-content">
              <h3>Seguro</h3>
              <p>Autenticação para proteger seus dados</p>
            </div>
          </div>
          
          <div className="home__feature">
            <div className="home__feature-icon">
              <Users size={20} />
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
              <p>Post com os detalhes</p>
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
              <h3>Combine a retirada</h3>
              <p>No campus, de forma segura</p>
            </div>
          </div>
        </div>
      </section>

      {/* Recent Items / Explorar */}
      <section className="home__feed">
        <h2 className="home__section-title">
          {recentItems.length > 0 ? 'Itens recentes' : 'Todos os itens'}
        </h2>
        
        {recentItems.length > 0 ? (
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
        ) : (
          !loading && (
            <p className="home__empty-msg">Nenhum item registrado ainda.</p>
          )
        )}
        
        <div className="home__see-all-wrapper">
          <Link to="/itens" className="home__see-all">
            <Eye size={16} />
            Explorar todos os itens
            <ArrowRight size={16} />
          </Link>
        </div>
      </section>

      {/* Final CTA */}
      <section className="home__cta">
        <h2>Comece agora mesmo</h2>
        <p>Junte-se à comunidade e ajude a encontrar objetos perdidos</p>
        <Link to="/cadastro" className="home__cta-btn">
          Criar conta grátis
        </Link>
      </section>
    </div>
  );
}