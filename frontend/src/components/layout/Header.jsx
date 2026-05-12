import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { LogOut, LayoutGrid } from 'lucide-react';
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

  return (
    <header className="header">
      <div className="header__inner">
        <div className="header__left">
          <Link to="/" className="header__logo">
            <img src={logoSideText} alt="Achei no Campus" className="header__logo-img" />
          </Link>

          <Link 
            to="/itens" 
            className={`header__nav-link ${location.pathname === '/itens' ? 'header__nav-link--active' : ''}`}
          >
            <LayoutGrid size={16} strokeWidth={2} />
            Explorar
          </Link>
        </div>

        {signed ? (
          <div className="header__user-actions">
            <Link to="/perfil" className="header__user-btn" aria-label="Perfil">
              <span className="header__user-avatar">
                {user?.name?.charAt(0)?.toUpperCase() || 'U'}
              </span>
            </Link>
            <button onClick={handleLogout} className="header__logout-btn" aria-label="Sair">
              <LogOut size={18} strokeWidth={2} />
            </button>
          </div>
        ) : (
          <Link to="/login" className="header__login-btn">
            Entrar
          </Link>
        )}
      </div>
    </header>
  );
}