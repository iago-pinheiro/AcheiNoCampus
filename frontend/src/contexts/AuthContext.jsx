import { useState, createContext, useContext } from 'react';

const AuthContext = createContext();

function loadInitialState() {
  try {
    const storedToken = localStorage.getItem('@AcheiNoCampus:token');
    const storedUser = localStorage.getItem('@AcheiNoCampus:user');
    if (storedToken && storedUser) {
      return { token: storedToken, user: JSON.parse(storedUser) };
    }
  } catch {
    // ignore parse errors
  }
  return { token: null, user: null };
}

export function AuthProvider({ children }) {
  const [state, setState] = useState(loadInitialState);
  const { user, token } = state;

  const login = async (email, password) => {
    try {
      const response = await fetch('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Erro ao fazer login');
      const newState = { user: data.user, token: data.token };
      setState(newState);
      localStorage.setItem('@AcheiNoCampus:token', data.token);
      localStorage.setItem('@AcheiNoCampus:user', JSON.stringify(data.user));
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  const register = async (name, email, ra, password) => {
    try {
      const response = await fetch('http://localhost:3000/api/auth/cadastro', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, ra, password }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Erro ao fazer cadastro');
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  const logout = () => {
    setState({ user: null, token: null });
    localStorage.removeItem('@AcheiNoCampus:token');
    localStorage.removeItem('@AcheiNoCampus:user');
  };

  return (
    <AuthContext.Provider value={{ signed: !!user, user, token, loading: false, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth deve ser usado dentro de um AuthProvider');
  return context;
}
