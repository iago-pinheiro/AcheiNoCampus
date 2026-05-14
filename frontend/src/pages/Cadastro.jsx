import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { User, Mail, Lock, Hash, ArrowRight, ChevronLeft } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { Input } from '../components/ui/Input';
import { Button } from '../components/ui/Button';
import './Auth.css';

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
      navigate('/login');
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
          <h1 className="auth__title">Crie sua conta</h1>
          <p className="auth__subtitle">Junte-se à comunidade do campus</p>
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

          <div className="auth__submit">
            <Button type="submit" variant="primary" size="lg" fullWidth disabled={isSubmitting}>
              {isSubmitting ? 'Cadastrando...' : 'Criar Conta'}
            </Button>
          </div>
        </form>

        <div className="auth__footer">
          <p>Já tem uma conta?</p>
          <Link to="/login" className="auth__link">
            Faça login <ArrowRight size={16} />
          </Link>
        </div>
      </motion.div>
    </div>
  );
}
