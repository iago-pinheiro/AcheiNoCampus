import { Link, useNavigate, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useAuth } from '../../contexts/AuthContext';
import { LogOut, LayoutGrid, PlusCircle, Home } from 'lucide-react';
import logoSideText from '../../assets/logo_side_text_nav.png';
import './Header.css';

export function Header() {
  const location = useLocation();
  const navigate = useNavigate();
  const { signed, logout, user } = useAuth();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const isActive = (path) => location.pathname === path;

  return (
    <motion.header
      className="header"
      initial={{ y: -20, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.3, ease: 'easeOut' }}
    >
      <div className="header__inner">
        <div className="header__left">
          <Link to="/" className="header__logo" aria-label="Início">
            <img src={logoSideText} alt="Achei no Campus" className="header__logo-img" />
          </Link>

          <nav className="header__nav" aria-label="Navegação principal">
            <Link
              to="/"
              className={`header__nav-link ${isActive('/') ? 'header__nav-link--active' : ''}`}
            >
              <Home size={18} />
              <span>Início</span>
            </Link>
            <Link
              to="/itens"
              className={`header__nav-link ${isActive('/itens') ? 'header__nav-link--active' : ''}`}
            >
              <LayoutGrid size={18} />
              <span>Explorar</span>
            </Link>
            {signed && (
              <Link
                to="/postar"
                className={`header__nav-link ${isActive('/postar') ? 'header__nav-link--active' : ''}`}
              >
                <PlusCircle size={18} />
                <span>Postar</span>
              </Link>
            )}
          </nav>
        </div>

        <div className="header__right">
          {signed ? (
            <>
              <Link to="/perfil" className="header__avatar" aria-label="Perfil">
                <span className="header__avatar-letter">
                  {user?.name?.charAt(0)?.toUpperCase() || 'U'}
                </span>
              </Link>
              <button onClick={handleLogout} className="header__icon-btn" aria-label="Sair">
                <LogOut size={20} />
              </button>
            </>
          ) : (
            <Link to="/login" className="header__login-btn">
              Entrar
            </Link>
          )}
        </div>
      </div>
    </motion.header>
  );
}
