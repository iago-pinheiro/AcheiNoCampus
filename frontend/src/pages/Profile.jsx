import { useAuth } from '../contexts/AuthContext';
import './Home.css'; // reaproveitando os estilos de layout

export function Profile() {
  const { user } = useAuth();

  return (
    <section className="home">
      <div className="home__hero">
        <h1 className="home__title">Meu Perfil</h1>
        <p className="home__subtitle">Olá, {user?.name || 'Estudante'}! Gerencie seus itens abaixo.</p>
      </div>

      <div className="home__feed">
        <h2 className="home__section-title">Meus Itens</h2>
        <p className="home__status-msg">Você ainda não postou nenhum item.</p>
      </div>
    </section>
  );
}
