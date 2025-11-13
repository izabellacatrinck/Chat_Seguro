// Configuração da API - pode ser sobrescrita por variáveis de ambiente
// Por padrão, usa URLs relativas para aproveitar o proxy do Vite
// Se VITE_API_PORT ou VITE_API_HOST estiverem definidos, usa URLs absolutas
const API_PORT = import.meta.env.VITE_API_PORT
const API_HOST = import.meta.env.VITE_API_HOST

// Se as variáveis de ambiente estiverem definidas, usa URLs absolutas
// Caso contrário, usa URLs relativas (proxy do Vite)
export const API_BASE_URL = API_HOST || API_PORT 
  ? `http://${API_HOST || 'localhost'}:${API_PORT || '8000'}`
  : '' // URL relativa - será resolvida pelo proxy

export const WS_BASE_URL = API_HOST || API_PORT
  ? `ws://${API_HOST || 'localhost'}:${API_PORT || '8000'}`
  : (window.location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + window.location.host

