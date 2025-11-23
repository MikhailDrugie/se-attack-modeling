import React, { useEffect, useState } from 'react';
import {
  Container,
  Typography,
  Box,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  IconButton,
  Alert,
} from '@mui/material';
import { DataGrid } from '@mui/x-data-grid';
import type { GridColDef } from '@mui/x-data-grid';
import { Add as AddIcon, Delete as DeleteIcon } from '@mui/icons-material';
import { Navbar } from '../components/Navbar';
import { usersAPI } from '../services/api';
import { useTranslation } from 'react-i18next';
import { UserRole, UserRoleLabels } from '../types';
import type { User } from '../types';

export const UsersPage: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [openDialog, setOpenDialog] = useState(false);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');

  const [formData, setFormData] = useState({
    username: '',
    password: '',
    role: UserRole.DEV as number as UserRole,
  });

  const { t } = useTranslation();

  const loadUsers = async () => {
    try {
      const data = await usersAPI.getAll();
      setUsers(data);
    } catch (error) {
      console.error('Failed to load users:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const handleCreateUser = async () => {
    if (!formData.username || !formData.password) {
      setError('Заполните все поля');
      return;
    }

    setCreating(true);
    setError('');

    try {
      await usersAPI.create({
        username: formData.username,
        email: `${formData.username}@example.com`, // TODO: временно, если бэк требует email
        password: formData.password,
        role: formData.role.toString(),
      });
      setOpenDialog(false);
      setFormData({ username: '', password: '', role: UserRole.DEV });
      loadUsers();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Ошибка создания пользователя');
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteUser = async (id: number) => {
    if (!confirm('Удалить пользователя?')) return;

    try {
      // await usersAPI.delete(id); // TODO
      id;
      loadUsers();
    } catch (error) {
      console.error('Failed to delete user:', error);
    }
  };

  const columns: GridColDef[] = [
    { field: 'id', headerName: 'ID', width: 70 },
    { field: 'username', headerName: t('common.username'), flex: 1 },
    {
      field: 'role',
      headerName: t('common.role'),
      width: 150,
      renderCell: (params) => t(UserRoleLabels[params.value as UserRole]),
    },
    {
      field: 'created_at',
      headerName: 'Создан',
      width: 180,
      renderCell: (params) => new Date(params.value).toLocaleString(),
    },
    {
      field: 'actions',
      headerName: t('common.actions'),
      width: 100,
      sortable: false,
      renderCell: (params) => (
        <IconButton size="small" onClick={() => handleDeleteUser(params.row.id)}>
          <DeleteIcon />
        </IconButton>
      ),
    },
  ];

  return (
    <>
      <Navbar />
      <Container maxWidth="lg" sx={{ mt: 4 }}>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
          <Typography variant="h4">{t('users.title')}</Typography>
          <Button variant="contained" startIcon={<AddIcon />} onClick={() => setOpenDialog(true)}>
            {t('users.newUser')}
          </Button>
        </Box>

        <Box sx={{ height: 600, width: '100%' }}>
          <DataGrid
            rows={users}
            columns={columns}
            loading={loading}
            pageSizeOptions={[10, 25, 50]}
            initialState={{
              pagination: { paginationModel: { pageSize: 10 } },
            }}
          />
        </Box>

        <Dialog open={openDialog} onClose={() => setOpenDialog(false)} maxWidth="sm" fullWidth>
          <DialogTitle>{t('users.newUser')}</DialogTitle>
          <DialogContent>
            {error && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {error}
              </Alert>
            )}

            <TextField
              label={t('common.username')}
              fullWidth
              margin="normal"
              value={formData.username}
              onChange={(e) => setFormData({ ...formData, username: e.target.value })}
            />

            <TextField
              label={t('common.password')}
              type="password"
              fullWidth
              margin="normal"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
            />

            <FormControl fullWidth margin="normal">
              <InputLabel>{t('common.role')}</InputLabel>
              <Select
                    value={formData.role}
                    onChange={(e) => setFormData({ ...formData, role: e.target.value as number as UserRole })}
                    label={t('common.role')}
                    >
                    <MenuItem value={UserRole.DEV}>{t('users.roleDev')}</MenuItem>
                    <MenuItem value={UserRole.ANALYST}>{t('users.roleAnalyst')}</MenuItem>
                    <MenuItem value={UserRole.ADMIN}>{t('users.roleAdmin')}</MenuItem>
                </Select>
            </FormControl>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setOpenDialog(false)}>{t('common.cancel')}</Button>
            <Button onClick={handleCreateUser} disabled={creating} variant="contained">
              {creating ? t('common.loading') : t('common.create')}
            </Button>
          </DialogActions>
        </Dialog>
      </Container>
    </>
  );
};
