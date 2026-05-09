import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';

export function ProtectedRoute() {
  const { signed, loading } = useAuth();

  if (loading) {
    return <div style={{ display: 'flex', justifyContent: 'center', padding: '3rem' }}>Carregando...</div>;
  }

  // Se não estiver logado, redireciona para a tela de login
  return signed ? <Outlet /> : <Navigate to="/login" replace />;
}
