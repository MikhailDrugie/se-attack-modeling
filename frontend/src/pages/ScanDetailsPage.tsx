import React, { useEffect, useState } from 'react';
import {
  Container,
  Typography,
  Box,
  Card,
  CardContent,
  CircularProgress,
  Chip,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Button,
} from '@mui/material';
import { ArrowBack as BackIcon, Download as DownloadIcon } from '@mui/icons-material';
import { useParams, useNavigate } from 'react-router-dom';
import { Navbar } from '../components/Navbar';
import api, { scansAPI } from '../services/api';
import { useTranslation } from 'react-i18next';
import {
  ScanStatus,
  ScanStatusLabels,
  VulnerabilitySeverityLabels,
  SeverityColors,
} from '../types';
import type { Scan, Vulnerability } from '../types';

export const ScanDetailsPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { t } = useTranslation();

  const [scan, setScan] = useState<Scan | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadData = async () => {
      if (!id) return;

      try {
        const scanData = await scansAPI.getById(Number(id));
        setScan(scanData);

        if (scanData.status === ScanStatus.COMPLETED) {
          const vulnData = scanData.vulnerabilities || [];
          setVulnerabilities(vulnData);
        }
      } catch (error) {
        console.error('Failed to load scan details:', error);
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, [id]);

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

  if (!scan) {
    return (
      <>
        <Navbar />
        <Container maxWidth="lg" sx={{ mt: 4 }}>
          <Alert severity="error">Сканирование не найдено</Alert>
        </Container>
      </>
    );
  }

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

  return (
    <>
      <Navbar />
      <Container maxWidth="lg" sx={{ mt: 4 }}>
        <Button startIcon={<BackIcon />} onClick={() => navigate('/scans')} sx={{ mb: 2 }}>
          Назад к списку
        </Button>

        {scan.status === ScanStatus.COMPLETED && (
          <>
            <Button
              variant="outlined"
              startIcon={<DownloadIcon />}
              onClick={async () => {
                try {
                  const response = await api.get(`/scans/${scan.id}/report/html`);
                  const htmlContent = response.data;
                  
                  // Открываем в новом окне
                  const newWindow = window.open();
                  newWindow!.document.write(htmlContent);
                  newWindow!.document.close();
                } catch (error) {
                  alert('Failed to generate report');
                }
              }}
            >
              Просмотр HTML
            </Button>

            <Button
              variant="contained"
              startIcon={<DownloadIcon />}
              onClick={async () => {
                try {
                  const response = await api.get(`/scans/${scan.id}/report/html/download`, {
                    responseType: 'blob'
                  });
                  
                  // Создаём blob URL
                  const blob = new Blob([response.data], { type: 'text/html' });
                  const url = window.URL.createObjectURL(blob);
                  
                  // Скачиваем
                  const link = document.createElement('a');
                  link.href = url;
                  link.download = `scan_report_${scan.id}.html`;
                  document.body.appendChild(link);
                  link.click();
                  document.body.removeChild(link);
                  
                  // Чистим
                  window.URL.revokeObjectURL(url);
                } catch (error) {
                  alert('Failed to download report');
                }
              }}
            >
              Скачать HTML
            </Button>

            <Button
              variant="contained"
              startIcon={<DownloadIcon />}
              onClick={async () => {
                try {
                  const response = await api.get(`/scans/${scan.id}/report/pdf`, {
                    responseType: 'blob'
                  });
                  // Создаём blob URL
                  const blob = new Blob([response.data], { type: 'application/pdf' });
                  const url = window.URL.createObjectURL(blob);
                  // Скачиваем
                  const link = document.createElement('a');
                  link.href = url;
                  link.download = `scan_report_${scan.id}.pdf`;
                  document.body.appendChild(link);
                  link.click();
                  document.body.removeChild(link);
                  window.URL.revokeObjectURL(url);
                } catch (error) {
                  console.error('Failed to download PDF report:', error);
                  alert('Failed to download PDF report');
                }
              }}
            >
              Скачать PDF
            </Button>

          </>
        )}

        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h5" gutterBottom>
              {t('scans.details')}
            </Typography>

            <Box sx={{ mt: 2 }}>
              <Typography variant="body1">
                <strong>{t('scans.targetUrl')}:</strong> {scan.target_url}
              </Typography>
              <Typography variant="body1" sx={{ mt: 1 }}>
                <strong>{t('scans.status')}:</strong>{' '}
                <Chip
                  label={t(ScanStatusLabels[scan.status])}
                  color={getStatusColor(scan.status)}
                  size="small"
                />
              </Typography>
              <Typography variant="body1" sx={{ mt: 1 }}>
                <strong>{t('scans.createdAt')}:</strong>{' '}
                {new Date(scan.created_at).toLocaleString()}
              </Typography>
              {scan.completed_at && (
                <Typography variant="body1" sx={{ mt: 1 }}>
                  <strong>Завершено:</strong> {new Date(scan.completed_at).toLocaleString()}
                </Typography>
              )}
              <Typography variant="body1" sx={{ mt: 1 }}>
                <strong>{t('scans.vulnerabilities')}:</strong> {vulnerabilities.length}
              </Typography>
            </Box>
          </CardContent>
        </Card>

        {scan.status === ScanStatus.COMPLETED && (
          <>
            <Typography variant="h5" gutterBottom>
              {t('vulnerabilities.title')}
            </Typography>

            {vulnerabilities.length === 0 ? (
              <Alert severity="success">{t('vulnerabilities.noVulnerabilities')}</Alert>
            ) : (
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>{t('vulnerabilities.severity')}</TableCell>
                      <TableCell>CWE</TableCell>
                      <TableCell>{t('vulnerabilities.name')}</TableCell>
                      <TableCell>{t('vulnerabilities.description')}</TableCell>
                      <TableCell>{t('vulnerabilities.affectedUrl')}</TableCell>
                      {/* <TableCell>{t('vulnerabilities.recommendation')}</TableCell> */}
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {vulnerabilities.map((vuln) => (
                      <TableRow key={vuln.id}>
                        <TableCell>
                          <Chip
                            label={t(VulnerabilitySeverityLabels[vuln.severity])}
                            color={SeverityColors[vuln.severity]}
                            size="small"
                          />
                        </TableCell>
                         <TableCell>
                          {vuln.cwe_id && vuln.cwe_id !== 'CWE-UNKNOWN' ? (
                            <Chip
                              label={vuln.cwe_id}
                              variant="outlined"
                              size="small"
                              onClick={() => {
                                window.open(`https://cwe.mitre.org/data/definitions/${vuln.cwe_id!.replace('CWE-', '')}.html`, '_blank')
                              }}
                              sx={{ cursor: 'pointer' }}
                            />
                          ) : (
                            '-'
                          )}
                        </TableCell>
                        <TableCell>{vuln.name}</TableCell>
                        <TableCell>{vuln.description || '-'}</TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {vuln.url_path}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </>
        )}

        {scan.status === ScanStatus.RUNNING && (
          <Alert severity="info" icon={<CircularProgress size={20} />}>
            Сканирование выполняется, пожалуйста подождите...
          </Alert>
        )}

        {scan.status === ScanStatus.FAILED && (
          <Alert severity="error">Сканирование завершилось с ошибкой</Alert>
        )}
      </Container>
    </>
  );
};
