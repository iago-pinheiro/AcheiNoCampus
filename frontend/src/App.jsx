import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Layout } from './components/layout/Layout';
import { Home } from './pages/Home';
import { AllItems } from './pages/AllItems';
import { PostItem } from './pages/PostItem';
import { ItemDetails } from './pages/ItemDetails';
import { Profile } from './pages/Profile';
import { Login } from './pages/Login';
import { Cadastro } from './pages/Cadastro';
import { AuthProvider } from './contexts/AuthContext';
import { ProtectedRoute } from './components/layout/ProtectedRoute';
import { ErrorBoundary } from './components/ErrorBoundary';

function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <Router>
          <Routes>
            <Route path="/" element={<Layout />}>
              <Route index element={<Home />} />
              <Route path="itens" element={<AllItems />} />
              <Route path="item/:id" element={<ItemDetails />} />
              <Route path="login" element={<Login />} />
              <Route path="cadastro" element={<Cadastro />} />
              
              {/* Rotas Protegidas */}
              <Route element={<ProtectedRoute />}>
                <Route path="postar" element={<PostItem />} />
                <Route path="perfil" element={<Profile />} />
              </Route>
            </Route>
          </Routes>
        </Router>
      </AuthProvider>
    </ErrorBoundary>
  );
}

export default App;
