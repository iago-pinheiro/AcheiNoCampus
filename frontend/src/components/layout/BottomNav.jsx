import { Link, useLocation } from 'react-router-dom';
import { Home, Search, PlusCircle, User, LogIn } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import './BottomNav.css';

export function BottomNav() {
  const location = useLocation();
  const { signed } = useAuth();

  const isActive = (path) => location.pathname === path;

  return (
    <nav className="bottom-nav" aria-label="Navegação principal">
      <Link 
        to="/" 
        className={`bottom-nav__item ${isActive('/') ? 'bottom-nav__item--active' : ''}`}
      >
        <Home size={24} strokeWidth={isActive('/') ? 2.5 : 2} />
        <span className="bottom-nav__label">Início</span>
      </Link>

      <Link 
        to="/itens" 
        className={`bottom-nav__item ${isActive('/itens') ? 'bottom-nav__item--active' : ''}`}
      >
        <Search size={24} strokeWidth={isActive('/itens') ? 2.5 : 2} />
        <span className="bottom-nav__label">Explorar</span>
      </Link>

      <Link 
        to="/postar" 
        className={`bottom-nav__item bottom-nav__item--action ${isActive('/postar') ? 'bottom-nav__item--active' : ''}`}
      >
        <PlusCircle size={28} strokeWidth={2.5} />
        <span className="bottom-nav__label">Postar</span>
      </Link>

      {signed ? (
        <Link 
          to="/perfil" 
          className={`bottom-nav__item ${isActive('/perfil') ? 'bottom-nav__item--active' : ''}`}
        >
          <User size={24} strokeWidth={isActive('/perfil') ? 2.5 : 2} />
          <span className="bottom-nav__label">Perfil</span>
        </Link>
      ) : (
        <Link 
          to="/login" 
          className={`bottom-nav__item ${isActive('/login') || isActive('/cadastro') ? 'bottom-nav__item--active' : ''}`}
        >
          <LogIn size={24} strokeWidth={2} />
          <span className="bottom-nav__label">Entrar</span>
        </Link>
      )}
    </nav>
  );
}