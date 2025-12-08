import React, { useEffect, useState } from 'react';
import {
  Container,
  Typography,
  Box,
  Card,
  CardContent,
  CircularProgress,
  Stack,
} from '@mui/material';
import {
  Security as SecurityIcon,
  BugReport as BugIcon,
  CheckCircle as CheckIcon,
} from '@mui/icons-material';
import { Navbar } from '../components/Navbar';
import { scansAPI } from '../services/api';
import { useTranslation } from 'react-i18next';
import { ScanStatus } from '../types';
import type { Scan } from '../types';

export const DashboardPage: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const { t } = useTranslation();

  useEffect(() => {
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

    loadScans();
  }, []);

  if (loading) {
    return (
      <>
        <Navbar />
        <Box display="flex" justifyContent="center" mt={4}>
          <CircularProgress />
        </Box>
      </>
    );
  }

  const totalScans = scans.length;
  const completedScans = scans.filter((s) => s.status === ScanStatus.COMPLETED).length;
  const runningScans = scans.filter((s) => s.status === ScanStatus.RUNNING).length;
  const totalVulnerabilities = scans.reduce((sum, s) => {
    return s.vulnerabilities_amount ? sum + s.vulnerabilities_amount : sum;
  }, 0);


  const stats = [
    {
      title: 'Всего сканирований',
      value: totalScans,
      icon: <SecurityIcon fontSize="large" />,
      color: '#1976d2',
    },
    {
      title: 'Завершено',
      value: completedScans,
      icon: <CheckIcon fontSize="large" />,
      color: '#2e7d32',
    },
    {
      title: 'В процессе',
      value: runningScans,
      icon: <CircularProgress size={40} />,
      color: '#ed6c02',
    },
    {
      title: 'Уязвимостей',
      value: totalVulnerabilities,
      icon: <BugIcon fontSize="large" />,
      color: '#d32f2f',
    },
  ];

  return (
    <>
      <Navbar />
      <Container maxWidth="lg" sx={{ mt: 4 }}>
        <Typography variant="h4" gutterBottom>
          {t('nav.dashboard')}
        </Typography>

        <Stack
          direction="row"
          spacing={3}
          sx={{
            mt: 3,
            flexWrap: 'wrap',
            '& > *': { flex: '1 1 calc(25% - 24px)', minWidth: '200px' }
          }}
        >
          {stats.map((stat, idx) => (
            <Card key={idx}>
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Box>
                    <Typography color="textSecondary" gutterBottom>
                      {stat.title}
                    </Typography>
                    <Typography variant="h4">{stat.value}</Typography>
                  </Box>
                  <Box sx={{ color: stat.color }}>{stat.icon}</Box>
                </Box>
              </CardContent>
            </Card>
          ))}
        </Stack>
      </Container>
    </>
  );
};
