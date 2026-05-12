import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { LogOut } from 'lucide-react';
import logoSideText from '../../assets/logo_side_text_nav.png';
import './Header.css';

export function Header() {
  const navigate = useNavigate();
  const { signed, logout, user } = useAuth();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header className="header">
      <div className="header__inner">
        <Link to="/" className="header__logo">
          <img src={logoSideText} alt="Achei no Campus" className="header__logo-img" />
        </Link>

        {signed ? (
          <div className="header__user-actions">
            <Link to="/perfil" className="header__user-btn" aria-label="Perfil">
              <span className="header__user-avatar">
                {user?.name?.charAt(0)?.toUpperCase() || 'U'}
              </span>
            </Link>
            <button onClick={handleLogout} className="header__logout-btn" aria-label="Sair">
              <LogOut size={18} />
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