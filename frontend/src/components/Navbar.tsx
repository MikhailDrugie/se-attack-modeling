import React from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Button,
  Box,
  IconButton,
} from '@mui/material';
import { Logout as LogoutIcon } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { LanguageSwitcher } from './LanguageSwitcher';
import { useTranslation } from 'react-i18next';
import { UserRole, UserRoleLabels } from '../types';

export const Navbar: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const { t } = useTranslation();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <AppBar position="static">
      <Toolbar>
        <Typography variant="h6" sx={{ flexGrow: 1 }}>
          {t('auth.loginTitle')}
        </Typography>

        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          <Button color="inherit" onClick={() => navigate('/')}>
            {t('nav.dashboard')}
          </Button>
          
          <Button color="inherit" onClick={() => navigate('/scans')}>
            {t('nav.scans')}
          </Button>

          <Button color="inherit" onClick={() => navigate('/cwe')}>
            {t('nav.cwe')}
          </Button>

          {user?.role === UserRole.ADMIN && (
            <Button color="inherit" onClick={() => navigate('/users')}>
              {t('nav.users')}
            </Button>
          )}

          <Typography variant="body2" sx={{ ml: 2 }}>
            {user?.username} ({user ? t(UserRoleLabels[user.role]) : ''})
          </Typography>

          <LanguageSwitcher />

          <IconButton color="inherit" onClick={handleLogout}>
            <LogoutIcon />
          </IconButton>
        </Box>
      </Toolbar>
    </AppBar>
  );
};
