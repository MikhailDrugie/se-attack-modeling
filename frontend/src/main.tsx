import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './i18n/config';  // импорт i18n конфига
import { CssBaseline } from '@mui/material';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <CssBaseline />  {/* MUI сброс стилей */}
    <App />
  </React.StrictMode>
);
