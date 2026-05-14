import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Mail, Lock, ArrowRight, ChevronLeft } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { Input } from '../components/ui/Input';
import { Button } from '../components/ui/Button';
import './Auth.css';

export function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!email || !password) {
      setError('Preencha todos os campos.');
      return;
    }
    setIsSubmitting(true);
    const result = await login(email, password);
    if (result.success) {
      navigate('/');
    } else {
      setError(result.error);
      setIsSubmitting(false);
    }
  };

  return (
    <div className="auth">
      <Link to="/" className="auth__back">
        <ChevronLeft size={22} />
      </Link>

      <motion.div
        className="auth__card"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <div className="auth__header">
          <div className="auth__logo">
            <span className="auth__logo-text">A</span>
          </div>
          <h1 className="auth__title">Bem-vindo de volta!</h1>
          <p className="auth__subtitle">Faça login para continuar</p>
        </div>

        {error && (
          <motion.div
            className="auth__error"
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
          >
            {error}
          </motion.div>
        )}

        <form onSubmit={handleSubmit} className="auth__form">
          <Input
            label="E-mail Acadêmico"
            type="email"
            placeholder="seu.email@universidade.edu.br"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            icon={<Mail size={18} />}
          />

          <Input
            label="Senha"
            type="password"
            placeholder="••••••••"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            icon={<Lock size={18} />}
          />

          <div className="auth__submit">
            <Button type="submit" variant="primary" size="lg" fullWidth disabled={isSubmitting}>
              {isSubmitting ? 'Entrando...' : 'Entrar'}
            </Button>
          </div>
        </form>

        <div className="auth__footer">
          <p>Não tem uma conta?</p>
          <Link to="/cadastro" className="auth__link">
            Cadastre-se <ArrowRight size={16} />
          </Link>
        </div>
      </motion.div>
    </div>
  );
}
