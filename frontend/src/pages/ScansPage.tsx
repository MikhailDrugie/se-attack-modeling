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
  // CircularProgress,
  Chip,
  IconButton,
} from '@mui/material';
import { DataGrid } from '@mui/x-data-grid';
import type { GridColDef } from '@mui/x-data-grid';
import { Add as AddIcon, Visibility as ViewIcon, Delete as DeleteIcon } from '@mui/icons-material';
import { Navbar } from '../components/Navbar';
import { scansAPI } from '../services/api';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { ScanStatus, ScanStatusLabels, UserRole } from '../types';
import { useAuth } from '../context/AuthContext';
import type { Scan } from '../types';

export const ScansPage: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [openDialog, setOpenDialog] = useState(false);
  const [targetUrl, setTargetUrl] = useState('');
  const [creating, setCreating] = useState(false);
  
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { user } = useAuth();

  const loadScans = async () => {
    try {
      const data = await scansAPI.getAll();
      setScans(data);
    } catch (error) {
      console.error('Failed to load scans:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScans();
  }, []);

  const handleCreateScan = async () => {
    if (!targetUrl) return;
    
    setCreating(true);
    try {
      await scansAPI.create(targetUrl/*, 'full'*/); // TODO: scan_type backend
      setOpenDialog(false);
      setTargetUrl('');
      loadScans();
    } catch (error) {
      console.error('Failed to create scan:', error);
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteScan = async (id: number) => {
    if (!confirm('Удалить сканирование?')) return;
    
    try {
      // await scansAPI.delete(id);
      id;
      loadScans();
    } catch (error) {
      console.error('Failed to delete scan:', error);
    }
  };

  const getStatusColor = (status: ScanStatus) => {
    switch (status) {
      case ScanStatus.COMPLETED:
        return 'success';
      case ScanStatus.RUNNING:
        return 'warning';
      case ScanStatus.FAILED:
        return 'error';
      default:
        return 'default';
    }
  };

  const columns: GridColDef[] = [
    { field: 'id', headerName: 'ID', width: 70 },
    { field: 'target_url', headerName: t('scans.targetUrl'), flex: 1 },
    {
      field: 'status',
      headerName: t('scans.status'),
      width: 150,
      renderCell: (params) => (
        <Chip
          label={t(ScanStatusLabels[params.value as ScanStatus])}
          color={getStatusColor(params.value as ScanStatus)}
          size="small"
        />
      ),
    },
    {
      field: 'vulnerabilities',
      headerName: t('scans.vulnerabilities'),
      width: 130,
      renderCell: (params) => params.value.length,
    },
    {
      field: 'created_at',
      headerName: t('scans.createdAt'),
      width: 180,
      renderCell: (params) => new Date(params.value).toLocaleString(),
    },
    {
      field: 'actions',
      headerName: t('common.actions'),
      width: 120,
      sortable: false,
      renderCell: (params) => (
        <Box>
          <IconButton size="small" onClick={() => navigate(`/scans/${params.row.id}`)}>
            <ViewIcon />
          </IconButton>
          <IconButton size="small" onClick={() => handleDeleteScan(params.row.id)}>
            <DeleteIcon />
          </IconButton>
        </Box>
      ),
    },
  ];

  const canCreateScan = user && (user.role === UserRole.ANALYST || user.role === UserRole.ADMIN);

  return (
    <>
      <Navbar />
      <Container maxWidth="lg" sx={{ mt: 4 }}>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
          <Typography variant="h4">{t('scans.title')}</Typography>
          {canCreateScan && (
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={() => setOpenDialog(true)}
            >
              {t('scans.newScan')}
            </Button>
          )}
        </Box>

        <Box sx={{ height: 600, width: '100%' }}>
          <DataGrid
            rows={scans}
            columns={columns}
            loading={loading}
            pageSizeOptions={[10, 25, 50]}
            initialState={{
              pagination: { paginationModel: { pageSize: 10 } },
            }}
          />
        </Box>

        <Dialog open={openDialog} onClose={() => setOpenDialog(false)} maxWidth="sm" fullWidth>
          <DialogTitle>{t('scans.newScan')}</DialogTitle>
          <DialogContent>
            <TextField
              label={t('scans.targetUrl')}
              fullWidth
              margin="normal"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com"
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setOpenDialog(false)}>{t('common.cancel')}</Button>
            <Button onClick={handleCreateScan} disabled={creating || !targetUrl} variant="contained">
              {creating ? t('common.loading') : t('scans.startScan')}
            </Button>
          </DialogActions>
        </Dialog>
      </Container>
    </>
  );
};
