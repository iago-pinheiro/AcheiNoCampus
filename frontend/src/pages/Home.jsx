import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { SearchBar } from '../components/ui/SearchBar';
import { CardItem } from '../components/ui/CardItem';
import { ReportItemButton } from '../components/ui/ActionButtons';
import { itemsApi } from '../services/api';
import './Home.css';

export function Home() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    async function fetchItems() {
      try {
        const data = await itemsApi.getAll();
        setItems(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    fetchItems();
  }, []);

  const filteredItems = items.filter(item => 
    item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    item.location.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <section className="home">
      <div className="home__hero">
        <h1 className="home__title">Achei no Campus</h1>
        <p className="home__subtitle">A plataforma de achados e perdidos confiável da sua universidade.</p>
        
        <div className="home__search-container">
          <SearchBar 
            placeholder="Encontre o seu item perdido..." 
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onAddClick={() => navigate('/postar')}
          />
        </div>
      </div>

      <div className="home__feed">
        <div className="home__feed-header">
          <h2 className="home__section-title">Publicações recentes</h2>
          <ReportItemButton onClick={() => navigate('/postar')} className="home__report-btn-mobile" />
        </div>
        
        {loading && <p className="home__status-msg">Carregando itens...</p>}
        {error && <p className="home__status-msg error-message">{error}</p>}
        
        {!loading && !error && filteredItems.length === 0 && (
          <p className="home__status-msg">Nenhum item encontrado no momento.</p>
        )}

        {!loading && !error && filteredItems.length > 0 && (
          <div className="home__grid">
            {filteredItems.map((item) => {
              // Convert API status to design system status
              const statusMap = {
                'FOUND': 'found',
                'LOST': 'pending',
                'RESOLVED': 'resolved'
              };
              const dsStatus = statusMap[item.status] || 'pending';

              return (
                <Link to={`/item/${item.id}`} key={item.id} className="home__card-link">
                  <CardItem 
                    title={item.title}
                    location={item.location}
                    date={new Date(item.createdAt).toLocaleDateString('pt-BR')}
                    status={dsStatus}
                    imageUrl={item.imageUrl}
                  />
                </Link>
              );
            })}
          </div>
        )}
      </div>
    </section>
  );
}
