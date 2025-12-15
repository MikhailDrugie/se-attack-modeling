import React, { useEffect, useState } from 'react';
import { Container, Typography, Card, CardContent, Chip, Box, Link } from '@mui/material';
import { Navbar } from '../components/Navbar';
import { cweAPI } from '../services/api';
import type { CWE } from '../types';

export const CWEPage: React.FC = () => {
  const [cwes, setCwes] = useState<CWE[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadCWEs = async () => {
      try {
        const data = await cweAPI.getAll();
        setCwes(data);
      } catch (error) {
        console.error('Failed to load CWEs:', error);
      } finally {
        setLoading(false);
      }
    };
    loadCWEs();
  }, []);

  if (loading) return <Container>Loading...</Container>;

  return (
    <>
      <Navbar />
      <Container maxWidth="lg" sx={{ mt: 4 }}>
        <Typography variant="h4" gutterBottom>
          CWE Knowledge Base
        </Typography>
        
        <Box
        sx={{
            display: 'grid',
            gridTemplateColumns: { xs: '1fr', md: 'repeat(2, 1fr)' },
            gap: 3,
        }}
        >
        {cwes.map((cwe) => (
            <Card key={cwe.id}>
            <CardContent>
                <Typography variant="h6" gutterBottom>
                {cwe.id}: {cwe.name}
                </Typography>
                
                <Chip label={cwe.severity} size="small" sx={{ mb: 2 }} />
                
                <Typography variant="body2" color="text.secondary" paragraph>
                {cwe.description}
                </Typography>
                
                {cwe.owasp_mapping && cwe.owasp_mapping.length > 0 && (
                <Typography variant="caption" display="block">
                    OWASP: {cwe.owasp_mapping.join(', ')}
                </Typography>
                )}
                
                {cwe.references && cwe.references.length > 0 && (
                <Link href={cwe.references[0]} target="_blank" sx={{ mt: 1, display: 'block' }}>
                    Learn more →
                </Link>
                )}
            </CardContent>
            </Card>
        ))}
        </Box>

      </Container>
    </>
  );
};
