const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

const getHeaders = (includeAuth = false) => {
  const headers = {
    'Content-Type': 'application/json',
  };
  if (includeAuth) {
    const token = localStorage.getItem('@AcheiNoCampus:token');
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
  }
  return headers;
};

const handleResponse = async (response) => {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `Erro ${response.status}`);
  }
  return data;
};

export const api = {
  get: async (path, options = {}) => {
    const response = await fetch(`${BASE_URL}${path}`, {
      ...options,
      headers: { ...getHeaders(options.includeAuth), ...options.headers },
    });
    return handleResponse(response);
  },

  post: async (path, body, includeAuth = false) => {
    const response = await fetch(`${BASE_URL}${path}`, {
      method: 'POST',
      headers: getHeaders(includeAuth),
      body: JSON.stringify(body),
    });
    return handleResponse(response);
  },

  patch: async (path, body, includeAuth = false) => {
    const response = await fetch(`${BASE_URL}${path}`, {
      method: 'PATCH',
      headers: getHeaders(includeAuth),
      body: JSON.stringify(body),
    });
    return handleResponse(response);
  },

  delete: async (path, includeAuth = false) => {
    const response = await fetch(`${BASE_URL}${path}`, {
      method: 'DELETE',
      headers: getHeaders(includeAuth),
    });
    return handleResponse(response);
  },
};

export const itemsApi = {
  getAll: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return api.get(`/api/items${query ? `?${query}` : ''}`);
  },

  getById: (id) => api.get(`/api/items/${id}`),

  create: (data) => api.post('/api/items', data, true),

  resolve: (id) => api.patch(`/api/items/${id}/resolve`, {}, true),
};

export const categoriesApi = {
  getAll: () => api.get('/api/categories'),
};