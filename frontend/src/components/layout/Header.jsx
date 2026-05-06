import { Link, useLocation } from 'react-router-dom';
import './Header.css';

export function Header() {
  const location = useLocation();

  const navLinks = [
    { to: '/', label: 'Início' },
    { to: '/postar', label: 'Postar Item' },
    { to: '/perfil', label: 'Perfil' },
  ];

  return (
    <header className="header">
      <div className="header__inner">
        <Link to="/" className="header__logo">
          Achei<span>NoCampus</span>
        </Link>

        <nav className="header__nav" aria-label="Navegação principal">
          {navLinks.map(({ to, label }) => (
            <Link
              key={to}
              to={to}
              className={`header__link ${location.pathname === to ? 'header__link--active' : ''}`}
            >
              {label}
            </Link>
          ))}
        </nav>
      </div>
    </header>
  );
}
