import { createContext, useState, useEffect, useContext } from 'react';

const AuthContext = createContext({});

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);

  // Inicializa o estado com base no localStorage
  useEffect(() => {
    const storedToken = localStorage.getItem('@AcheiNoCampus:token');
    const storedUser = localStorage.getItem('@AcheiNoCampus:user');

    if (storedToken && storedUser) {
      setToken(storedToken);
      setUser(JSON.parse(storedUser));
    }
    
    setLoading(false);
  }, []);

  const login = async (email, password) => {
    try {
      const response = await fetch('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Erro ao fazer login');
      }

      // Salvar no estado e localStorage
      setUser(data.user);
      setToken(data.token);
      
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
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name, email, ra, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Erro ao fazer cadastro');
      }

      // Após cadastro bem-sucedido, o backend no AcheiNoCampus retorna o user mas não o token.
      // O usuário terá que fazer login ou podemos logar automaticamente.
      // Retornaremos success para redirecionar o usuário para tela de login.
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('@AcheiNoCampus:token');
    localStorage.removeItem('@AcheiNoCampus:user');
  };

  return (
    <AuthContext.Provider value={{ signed: !!user, user, token, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth deve ser usado dentro de um AuthProvider');
  }
  return context;
}
