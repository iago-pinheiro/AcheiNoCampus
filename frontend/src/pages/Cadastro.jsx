import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { User, Mail, Lock, Hash } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { Input } from '../components/ui/Input';
import { Button } from '../components/ui/Button';
import './Auth.css'; // reaproveitando os estilos

export function Cadastro() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [ra, setRa] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  
  const { register } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    if (!name || !email || !password || !ra) {
      setError('Preencha todos os campos obrigatórios.');
      return;
    }

    setIsSubmitting(true);
    
    const result = await register(name, email, ra, password);
    
    if (result.success) {
      // Após o cadastro no backend, o usuário não é logado automaticamente
      // Então redirecionamos para o login
      navigate('/login');
    } else {
      setError(result.error);
      setIsSubmitting(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <h1 className="auth-title">Crie sua conta</h1>
          <p className="auth-subtitle">Junte-se à comunidade do campus.</p>
        </div>

        {error && <div className="auth-error">{error}</div>}

        <form onSubmit={handleSubmit} className="auth-form">
          <Input 
            label="Nome Completo" 
            type="text" 
            placeholder="João da Silva"
            value={name}
            onChange={(e) => setName(e.target.value)}
            icon={<User size={18} />}
          />

          <Input 
            label="E-mail Acadêmico" 
            type="email" 
            placeholder="seu.email@universidade.edu.br"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            icon={<Mail size={18} />}
          />

          <Input 
            label="RA / Matrícula" 
            type="text" 
            placeholder="Ex: 202300123"
            value={ra}
            onChange={(e) => setRa(e.target.value)}
            icon={<Hash size={18} />}
          />
          
          <Input 
            label="Senha" 
            type="password" 
            placeholder="••••••••"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            icon={<Lock size={18} />}
          />

          <div className="auth-actions">
            <Button type="submit" fullWidth disabled={isSubmitting}>
              {isSubmitting ? 'Cadastrando...' : 'Criar Conta'}
            </Button>
          </div>
        </form>

        <div className="auth-footer">
          Já tem uma conta? <Link to="/login" className="auth-link">Faça Login</Link>
        </div>
      </div>
    </div>
  );
}
