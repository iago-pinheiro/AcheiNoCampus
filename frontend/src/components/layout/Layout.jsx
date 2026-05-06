import { Outlet } from 'react-router-dom';
import { Header } from './Header';
import './Layout.css';

export function Layout() {
  return (
    <div className="app-shell">
      <Header />
      <main className="main-container">
        <Outlet />
      </main>
    </div>
  );
}
