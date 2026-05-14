import { Link, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Home, LayoutGrid, PlusCircle, User, LogIn } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import './BottomNav.css';

export function BottomNav() {
  const location = useLocation();
  const { signed } = useAuth();

  const isActive = (path) => location.pathname === path;

  return (
    <motion.nav
      className="bottom-nav"
      initial={{ y: 100 }}
      animate={{ y: 0 }}
      transition={{ duration: 0.3, ease: 'easeOut', delay: 0.1 }}
      aria-label="Navegação principal"
    >
      <Link
        to="/"
        className={`bottom-nav__item ${isActive('/') ? 'bottom-nav__item--active' : ''}`}
      >
        <div className={`bottom-nav__icon ${isActive('/') ? 'bottom-nav__icon--active' : ''}`}>
          <Home size={22} />
        </div>
        <span className="bottom-nav__label">Início</span>
      </Link>

      <Link
        to="/itens"
        className={`bottom-nav__item ${isActive('/itens') ? 'bottom-nav__item--active' : ''}`}
      >
        <div className={`bottom-nav__icon ${isActive('/itens') ? 'bottom-nav__icon--active' : ''}`}>
          <LayoutGrid size={22} />
        </div>
        <span className="bottom-nav__label">Explorar</span>
      </Link>

      <Link
        to="/postar"
        className={`bottom-nav__item bottom-nav__item--action ${isActive('/postar') ? 'bottom-nav__item--active' : ''}`}
      >
        <div className="bottom-nav__fab">
          <PlusCircle size={28} />
        </div>
      </Link>

      {signed ? (
        <Link
          to="/perfil"
          className={`bottom-nav__item ${isActive('/perfil') ? 'bottom-nav__item--active' : ''}`}
        >
          <div className={`bottom-nav__icon ${isActive('/perfil') ? 'bottom-nav__icon--active' : ''}`}>
            <User size={22} />
          </div>
          <span className="bottom-nav__label">Perfil</span>
        </Link>
      ) : (
        <Link
          to="/login"
          className={`bottom-nav__item ${isActive('/login') || isActive('/cadastro') ? 'bottom-nav__item--active' : ''}`}
        >
          <div className={`bottom-nav__icon ${isActive('/login') || isActive('/cadastro') ? 'bottom-nav__icon--active' : ''}`}>
            <LogIn size={22} />
          </div>
          <span className="bottom-nav__label">Entrar</span>
        </Link>
      )}
    </motion.nav>
  );
}
