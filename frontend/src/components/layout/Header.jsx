import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { LogOut } from 'lucide-react';
import logoTitle from '../../assets/logo_title.png';
import logoMobile from '../../assets/logo_mobile.png';
import './Header.css';

export function Header() {
  const location = useLocation();
  const navigate = useNavigate();
  const { signed, logout } = useAuth();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header className="header">
      <div className="header__inner">
        <Link to="/" className="header__logo">
          <img src={logoMobile} alt="Ícone" className="header__logo-img" />
          <span className="header__logo-text">Achei no Campus</span>
        </Link>

        <nav className="header__nav" aria-label="Navegação principal">
          <Link to="/" className={`header__link ${location.pathname === '/' ? 'header__link--active' : ''}`}>
            Início
          </Link>
          <Link to="/postar" className={`header__link ${location.pathname === '/postar' ? 'header__link--active' : ''}`}>
            Postar Item
          </Link>
          
          {signed ? (
            <>
              <Link to="/perfil" className={`header__link ${location.pathname === '/perfil' ? 'header__link--active' : ''}`}>
                Perfil
              </Link>
              <button onClick={handleLogout} className="header__link" style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', border: 'none', background: 'transparent', cursor: 'pointer' }} aria-label="Sair">
                Sair <LogOut size={16} />
              </button>
            </>
          ) : (
            <Link to="/login" className={`header__link ${location.pathname === '/login' ? 'header__link--active' : ''}`} style={{ fontWeight: 600, color: 'var(--color-primary-blue)' }}>
              Entrar
            </Link>
          )}
        </nav>
      </div>
    </header>
  );
}
