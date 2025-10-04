import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
    Container, Box, Typography, Button, Paper, Grid,
    Table, TableBody, TableCell, TableContainer, TableHead, TableRow, 
    CircularProgress, Chip, IconButton, Snackbar
} from '@mui/material';
import { 
    CheckCircle, Error, Warning, PlayArrow, Settings,
    Refresh, ContentCopy, Email, FileDownload
} from '@mui/icons-material';

// Import the new Settings Modal component
import SettingsModal from './SettingsModal';

const API_BASE_URL = 'http://localhost:5000/api'; // Connects to the Flask backend

// Custom Status Chip Component
const StatusChip = ({ status, label }) => {
    const colorMap = {
        'OK': { color: 'success', icon: <CheckCircle /> },
        'ALERT': { color: 'error', icon: <Error /> },
        'N/A': { color: 'default', icon: <Warning /> },
        'MEDIUM': { color: 'warning', icon: <Warning /> },
        'HIGH': { color: 'error', icon: <Error /> },
        'SCANNING...': { color: 'primary', icon: <CircularProgress size={16} color="inherit" /> },
    };
    const finalStatus = colorMap[status] || colorMap['N/A'];
    return <Chip label={label || status} color={finalStatus.color} icon={finalStatus.icon} size="small" />;
};

// Main Dashboard Component
const Dashboard = () => {
    const [statusData, setStatusData] = useState({});
    const [inventory, setInventory] = useState([]);
    const [alerts, setAlerts] = useState([]);
    const [loading, setLoading] = useState(false);
    
    // Controls the visibility of the settings modal
    const [settingsOpen, setSettingsOpen] = useState(false); 
    const [configData, setConfigData] = useState({}); 
    // Toggle CSP/Header Visibility
    const [cspVisible, setCspVisible] = useState(false); 
    
    const [snackbarOpen, setSnackbarOpen] = useState(false);
    const [snackbarMessage, setSnackbarMessage] = useState("");

    const fetchData = async () => {
        setLoading(true);
        try {
            const [statusRes, inventoryRes, alertsRes, configRes] = await Promise.all([
                axios.get(`${API_BASE_URL}/status`),
                axios.get(`${API_BASE_URL}/inventory`),
                axios.get(`${API_BASE_URL}/alerts`),
                axios.get(`${API_BASE_URL}/config`) // Fetch config for headers
            ]);
            setStatusData(statusRes.data);
            setInventory(inventoryRes.data);
            setAlerts(alertsRes.data);
            setConfigData(configRes.data); // Set the config state
        } catch (error) {
            console.error("Error fetching data:", error);
            setSnackbarMessage("Failed to fetch data from the backend. Is Python server running?");
            setSnackbarOpen(true);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 60000); 
        return () => clearInterval(interval);
    }, []);

    // Function to scroll to the alerts section
    const scrollToAlerts = () => {
        const alertsSection = document.getElementById('tampering-alerts-anchor');
        if (alertsSection) {
            alertsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    };


    const handleRunScan = async () => {
        setLoading(true);
        // Temporarily set the status to indicate activity
        setStatusData(prev => ({ ...prev, compliance_status: 'SCANNING...' })); 
        
        try {
            // CRITICAL FIX: POST request runs the scan on the backend
            await axios.post(`${API_BASE_URL}/scan`);
            setSnackbarMessage("Scan initiated. Forcing update...");
            setSnackbarOpen(true);
            
            // CRITICAL FIX: Wait for the backend to finish writing the alert to the log 
            setTimeout(fetchData, 1500); 
            
        } catch (error) {
            setSnackbarMessage("Error running scan. Check backend console.");
            setSnackbarOpen(true);
        } finally {
            // Loading is handled by the delayed fetchData
        }
    };

    const handleSetBaseline = async (scriptId) => {
        try {
            await axios.post(`${API_BASE_URL}/baseline/${scriptId}`);
            setSnackbarMessage(`Baseline for ${scriptId} successfully reset.`);
            setSnackbarOpen(true);
            await fetchData();
        } catch (error) {
            setSnackbarMessage("Error resetting baseline. Script may not be in ALERT state.");
            setSnackbarOpen(true);
        }
    };

    // Export Function
    const handleExport = () => {
        if (!inventory.length) {
            setSnackbarMessage("No data to export.");
            setSnackbarOpen(true);
            return;
        }

        const headers = [
            "Group", "Source/Snippet", "SRI Applied", "Tamper Status", 
            "Baseline Hash", "Justification"
        ];
        
        // Map the inventory array to a CSV-friendly format
        const csv = inventory.map(row => [
            // Use double quotes for strings that might contain commas
            `"${row.type}"`,
            `"${(row.source || row.content_snippet).replace(/"/g, '""')}"`, // Escape inner quotes
            `"${row.sri_applied ? 'APPLIED' : 'MISSING'}"`,
            `"${row.status}"`,
            `"${row.baseline_hash}"`,
            `"${row.justification}"`
        ].join(','));

        const csvString = [
            headers.join(','),
            ...csv
        ].join('\n');

        // Trigger the download
        const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.setAttribute('download', `PCI_Scripts_Inventory_${new Date().toISOString().slice(0, 10)}.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };


    const formatTimestamp = (ts) => {
        return ts !== 'N/A' ? new Date(ts).toLocaleString() : ts;
    };
    
    // Find the header status object for the CSP panel
    const headerStatus = inventory.find(s => s.id === 'headers');
    const cspContent = headerStatus?.content?.['Content-Security-Policy'];


    return (
        <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
            <Typography variant="h4" gutterBottom>
                💳 PCI DSS 6.4.3 & 11.6.1 Compliance Dashboard
            </Typography>

            {/* --- Status Header and Action Buttons --- */}
            <Paper elevation={3} sx={{ p: 3, mb: 4, bgcolor: '#f5f5f5' }}>
                <Grid container spacing={3} alignItems="center">
                    {/* CLICKABLE STATUS TO SCROLL TO ALERTS */}
                    <Grid item xs={12} md={4} onClick={scrollToAlerts} style={{ cursor: 'pointer' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                            {/* FINAL STATUS FIX: If status is OK but CSP is missing, visually force ALERT */}
                            <StatusChip 
                                status={(statusData.compliance_status === 'OK' && !cspContent) ? 'ALERT' : statusData.compliance_status} 
                            />
                            <Typography variant="h6" sx={{ ml: 2, textDecoration: 'underline' }}>
                                Overall Compliance Status
                            </Typography>
                        </Box>
                        <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                            Last Scan: {formatTimestamp(statusData.last_scan)}
                        </Typography>
                    </Grid>
                    {/* END CLICKABLE STATUS */}

                    <Grid item xs={12} md={4}>
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                            <Email color="error" sx={{ mr: 1 }} />
                            <Typography variant="h6">
                                Unresolved Alerts: {statusData.alert_count || 0}
                            </Typography>
                        </Box>
                        <Typography variant="body2" color="textSecondary">
                            Personnel alerted for all HIGH severity issues.
                        </Typography>
                    </Grid>
                    <Grid item xs={12} md={4} sx={{ textAlign: 'right' }}>
                        <Button
                            variant="contained"
                            color="primary"
                            startIcon={<PlayArrow />}
                            onClick={handleRunScan}
                            disabled={loading}
                            sx={{ mr: 1 }}
                        >
                            {loading ? <CircularProgress size={24} color="inherit" /> : 'Run Manual Scan'}
                        </Button>
                        <IconButton color="default" onClick={() => setSettingsOpen(true)}>
                            <Settings />
                        </IconButton>
                        <IconButton color="default" onClick={fetchData} disabled={loading}>
                            <Refresh />
                        </IconButton>
                    </Grid>
                </Grid>
            </Paper>

            {/* --- Tampering Alerts Log (PCI 11.6.1) --- */}
            {/* Section 1: ACTIVE TAMPERING / INTEGRITY ALERTS (HIGH Risk) */}
            <Typography variant="h5" gutterBottom sx={{ mt: 4 }} id="tampering-alerts-anchor">
                Active Tampering & Integrity Alerts (HIGH Risk)
            </Typography>
            <TableContainer component={Paper} sx={{ mb: 4 }}>
                <Table size="small">
                    <TableHead>
                        <TableRow>
                            <TableCell>Timestamp</TableCell>
                            <TableCell>Severity</TableCell>
                            <TableCell>Type</TableCell>
                            <TableCell>Location/Script</TableCell>
                            <TableCell>Details</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {alerts.filter(a => a.type.includes('Tamper') || a.type.includes('Modification')).length === 0 ? (
                            <TableRow><TableCell colSpan={5}>No active tampering or integrity alerts detected.</TableCell></TableRow>
                        ) : (
                            alerts.filter(a => a.type.includes('Tamper') || a.type.includes('Modification')).map((alert) => (
                                <TableRow key={alert.id} hover>
                                    <TableCell>{formatTimestamp(alert.timestamp)}</TableCell>
                                    <TableCell><StatusChip status={alert.severity} /></TableCell>
                                    <TableCell>{alert.type}</TableCell>
                                    <TableCell>{alert.location}</TableCell>
                                    <TableCell>{alert.details}</TableCell>
                                </TableRow>
                            ))
                        )}
                    </TableBody>
                </Table>
            </TableContainer>

            {/* Section 2: COMPLIANCE & SCAN ALERTS (Configuration & Failures) */}
            <Typography variant="h5" gutterBottom sx={{ mt: 4 }}>
                Compliance & Scan Configuration Alerts
            </Typography>
            <TableContainer component={Paper} sx={{ mb: 4 }}>
                <Table size="small">
                    <TableHead>
                        <TableRow>
                            <TableCell>Timestamp</TableCell>
                            <TableCell>Severity</TableCell>
                            <TableCell>Type</TableCell>
                            <TableCell>Location/Script</TableCell>
                            <TableCell>Details</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {alerts.filter(a => a.type.includes('Scan Failure') || a.type.includes('CSP Missing')).length === 0 ? (
                            <TableRow><TableCell colSpan={5}>No current configuration or scan alerts.</TableCell></TableRow>
                        ) : (
                            alerts.filter(a => a.type.includes('Scan Failure') || a.type.includes('CSP Missing')).map((alert) => (
                                <TableRow key={alert.id} hover>
                                    <TableCell>{formatTimestamp(alert.timestamp)}</TableCell>
                                    <TableCell><StatusChip status={alert.severity} /></TableCell>
                                    <TableCell>{alert.type}</TableCell>
                                    <TableCell>{alert.location}</TableCell>
                                    <TableCell>{alert.details}</TableCell>
                                </TableRow>
                            ))
                        )}
                    </TableBody>
                </Table>
            </TableContainer>

            {/* --- Security Header and CSP Panel (PCI 11.6.1) --- */}
            <Box sx={{ mb: 4 }}>
                <Typography variant="h5" sx={{ display: 'inline-block' }}>
                    Security Header Status (PCI 11.6.1)
                </Typography>
                {/* Toggle Button */}
                <Button 
                    size="small" 
                    onClick={() => setCspVisible(!cspVisible)} 
                    sx={{ ml: 2, mb: 1 }}
                >
                    {cspVisible ? 'Hide CSP Details' : 'Show CSP Details'}
                </Button>
                
                {cspVisible && (
                    <Paper elevation={3} sx={{ p: 3, bgcolor: '#fff' }}>
                        <Grid container spacing={3}>
                            <Grid item xs={12} md={6}>
                                <Typography variant="h6" color="textSecondary">
                                    Scan Target URL
                                </Typography>
                                <Typography variant="body1" sx={{ wordBreak: 'break-all' }}>
                                    {configData.url || 'Not configured'}
                                </Typography>
                                <Typography variant="h6" color="textSecondary" sx={{ mt: 2 }}>
                                    Header Tamper Status
                                </Typography>
                                <StatusChip 
                                    status={headerStatus?.status || 'N/A'} 
                                    label={headerStatus?.status || 'N/A'}
                                />
                            </Grid>
                            <Grid item xs={12} md={6}>
                                <Typography variant="h6" color="textSecondary">
                                    Content-Security-Policy (CSP)
                                </Typography>
                                <Box sx={{ 
                                    p: 1.5, 
                                    bgcolor: '#f0f0f0', 
                                    borderRadius: 1, 
                                    whiteSpace: 'pre-wrap', 
                                    fontSize: '0.85rem' 
                                }}>
                                    {cspContent || 'CSP HEADER MISSING (High Risk)'}
                                </Box>
                                <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                                    Baseline Hash: {headerStatus?.baseline_hash?.substring(0, 10) || 'N/A'}...
                                </Typography>
                            </Grid>
                        </Grid>
                    </Paper>
                )}
            </Box>


            {/* --- Script Inventory and Integrity (PCI 6.4.3) --- */}
            <Typography variant="h5" gutterBottom sx={{ mt: 4 }}>
                Script Inventory and Integrity Check (PCI 6.4.3)
            </Typography>
            {/* Export Button */}
            <Button
                variant="outlined"
                color="secondary"
                startIcon={<FileDownload />}
                onClick={handleExport}
                sx={{ mb: 2 }}
            >
                Export Script Table to CSV
            </Button>
            
            <TableContainer component={Paper}>
                <Table size="medium">
                    <TableHead>
                        <TableRow>
                            <TableCell>Group</TableCell>
                            <TableCell>Source/Snippet</TableCell>
                            <TableCell>Integrity (SRI)</TableCell>
                            <TableCell>Tamper Status</TableCell>
                            <TableCell>Baseline Hash</TableCell>
                            <TableCell>Justification</TableCell>
                            <TableCell>Actions</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {inventory.length === 0 && <TableRow><TableCell colSpan={7}>Run a scan to populate the script inventory.</TableCell></TableRow>}
                        {inventory.map((script) => (
                            <TableRow key={script.id} hover>
                                <TableCell>{script.type}</TableCell>
                                <TableCell>{script.source || script.content_snippet}</TableCell>
                                <TableCell>
                                    <StatusChip 
                                        status={script.sri_applied ? 'OK' : 'N/A'} 
                                        label={script.sri_applied ? 'APPLIED' : 'MISSING'} 
                                    />
                                </TableCell>
                                <TableCell><StatusChip status={script.status} /></TableCell>
                                <TableCell>
                                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                        {script.baseline_hash?.substring(0, 10)}...
                                        <IconButton size="small" onClick={() => navigator.clipboard.writeText(script.baseline_hash)}><ContentCopy sx={{ fontSize: 14 }} /></IconButton>
                                    </Box>
                                </TableCell>
                                <TableCell>{script.justification}</TableCell>
                                <TableCell>
                                    <Button 
                                        size="small" 
                                        disabled={script.status !== 'ALERT'} 
                                        onClick={() => handleSetBaseline(script.id)}
                                    >
                                        Set New Baseline
                                    </Button>
                                </TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </TableContainer>

            {/* Snackbar for notifications */}
            <Snackbar
                open={snackbarOpen}
                autoHideDuration={6000}
                onClose={() => setSnackbarOpen(false)}
                message={snackbarMessage}
                action={
                    <Button color="secondary" size="small" onClick={() => setSnackbarOpen(false)}>
                        DISMISS
                    </Button>
                }
            />
            
            {/* --- Settings Modal (NEW COMPONENT) --- */}
            <SettingsModal 
                open={settingsOpen}
                handleClose={() => setSettingsOpen(false)}
                onConfigSave={fetchData} // Refresh dashboard after saving config
            />
        </Container>
    );
};

export default Dashboard;