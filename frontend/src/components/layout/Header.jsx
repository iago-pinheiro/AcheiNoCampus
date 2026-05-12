import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { LogOut, User } from 'lucide-react';
import logoMobile from '../../assets/logo_mobile.png';
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
          <img src={logoMobile} alt="Achei no Campus" className="header__logo-img" />
          <span className="header__logo-text">Achei no Campus</span>
        </Link>

        {signed ? (
          <button onClick={handleLogout} className="header__user-btn" aria-label="Sair">
            <span className="header__user-avatar">
              {user?.name?.charAt(0)?.toUpperCase() || 'U'}
            </span>
          </button>
        ) : (
          <Link to="/login" className="header__login-btn">
            Entrar
          </Link>
        )}
      </div>
    </header>
  );
}