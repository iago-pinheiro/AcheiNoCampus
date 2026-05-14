import { Outlet, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Header } from './Header';
import { BottomNav } from './BottomNav';
import './Layout.css';

export function Layout() {
  const location = useLocation();

  const hideNav = location.pathname === '/login' || location.pathname === '/cadastro';

  return (
    <div className="app-shell">
      {!hideNav && <Header />}
      <main className="main-content">
        <motion.div
          key={location.pathname}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.15, ease: 'easeOut' }}
        >
          <Outlet />
        </motion.div>
      </main>
      {!hideNav && <BottomNav />}
    </div>
  );
}
