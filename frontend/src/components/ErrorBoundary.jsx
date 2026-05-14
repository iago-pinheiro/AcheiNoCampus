import { Component } from 'react';
import { Link } from 'react-router-dom';

export class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '100vh',
          padding: '24px',
          textAlign: 'center',
          background: '#F8FAFC',
          gap: '12px'
        }}>
          <div style={{
            width: '64px',
            height: '64px',
            borderRadius: '50%',
            background: 'rgba(239, 68, 68, 0.1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '28px'
          }}>
            ⚠️
          </div>
          <h1 style={{
            fontFamily: '"Plus Jakarta Sans", sans-serif',
            fontSize: '1.25rem',
            fontWeight: 700,
            color: '#0F172A',
            margin: 0
          }}>
            Algo deu errado
          </h1>
          <p style={{
            fontSize: '0.875rem',
            color: '#64748B',
            margin: 0,
            maxWidth: '300px'
          }}>
            Ocorreu um erro inesperado. Tente recarregar a página.
          </p>
          <Link
            to="/"
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{
              marginTop: '8px',
              padding: '10px 24px',
              borderRadius: '9999px',
              background: '#2553EB',
              color: '#fff',
              fontSize: '0.875rem',
              fontWeight: 600,
              textDecoration: 'none'
            }}
          >
            Voltar ao início
          </Link>
        </div>
      );
    }

    return this.props.children;
  }
}
