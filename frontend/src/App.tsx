// import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline } from '@mui/material';
import { AuthProvider } from './context/AuthContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { ScansPage } from './pages/ScansPage';
import { ScanDetailsPage } from './pages/ScanDetailsPage';
import { UsersPage } from './pages/UsersPage';
import { UserRole } from './types';
import { CWEPage } from './pages/CWEPage';

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            {/* Публичный роут */}
            <Route path="/login" element={<LoginPage />} />

            {/* Защищённые роуты */}
            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <DashboardPage />
                </ProtectedRoute>
              }
            />

            <Route
              path="/scans"
              element={
                <ProtectedRoute>
                  <ScansPage />
                </ProtectedRoute>
              }
            />

            <Route
              path="/scans/:id"
              element={
                <ProtectedRoute>
                  <ScanDetailsPage />
                </ProtectedRoute>
              }
            />

            <Route 
              path="/cwe" 
              element={
              <ProtectedRoute>
                  <CWEPage />
                </ProtectedRoute>
            } 
            />

            {/* Только для ADMIN */}
            <Route
              path="/users"
              element={
                <ProtectedRoute allowedRoles={[UserRole.ADMIN]}>
                  <UsersPage />
                </ProtectedRoute>
              }
            />

            {/* Fallback */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;
