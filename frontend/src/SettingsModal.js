import React, { useEffect, useState } from "react";
import { api } from "./api";  // Import api instead of axios
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Box,
  Typography,
  Divider,
  Alert,
} from "@mui/material";

export default function SettingsModal({ open, handleClose, onConfigSave }) {  // Remove apiBaseUrl prop
  const [url, setUrl] = useState("");
  const [emails, setEmails] = useState("");
  const [scanInterval, setScanInterval] = useState(3600);
  const [slackUrl, setSlackUrl] = useState("");
  const [teamsUrl, setTeamsUrl] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (open) {
      const fetchAllConfig = async () => {
        try {
          const [pageRes, notifyRes] = await Promise.all([
            api.get('/api/config'),  // Changed from axios to api
            api.get('/api/notifications-config'),  // Changed from axios to api
          ]);

          setUrl(pageRes.data.url || "");
          setEmails((pageRes.data.email_recipients || []).join(", "));
          setScanInterval(notifyRes.data.scan_interval || 3600);
          setSlackUrl(notifyRes.data.slack_url || "");
          setTeamsUrl(notifyRes.data.teams_url || "");
          setError("");
        } catch (err) {
          setError("Failed to load current configuration.");
        }
      };
      fetchAllConfig();
    }
  }, [open]);  // Removed apiBaseUrl dependency

  const handleSave = async () => {
    try {
      await api.post('/api/config', {  // Changed from axios to api
        url,
        emails: emails.split(",").map(e => e.trim()),
      });

      await api.post('/api/notifications-config', {  // Changed from axios to api
        scan_interval: parseInt(scanInterval, 10) || 3600,
        slack_url: slackUrl,
        teams_url: teamsUrl,
      });

      onConfigSave();
    } catch (err) {
      setError(err.response?.data?.message || "Failed to save settings.");
    }
  };

  return (
    <Dialog open={open} onClose={handleClose} fullWidth maxWidth="sm">
      <DialogTitle sx={{ fontWeight: 600 }}>Application Settings</DialogTitle>
      <DialogContent>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        
        <Box sx={{ my: 2 }}>
          <Typography variant="h6" gutterBottom>Monitoring</Typography>
          <TextField
            autoFocus
            margin="dense"
            id="url"
            label="URL to Monitor"
            type="url"
            fullWidth
            variant="outlined"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://your-payment-page.com"
          />
        </Box>

        <Divider sx={{ my: 2 }} />

        <Box sx={{ my: 2 }}>
          <Typography variant="h6" gutterBottom>Automated Scanning</Typography>
          <TextField
            margin="dense"
            id="scan-interval"
            label="Scan Interval (in seconds)"
            type="number"
            fullWidth
            variant="outlined"
            value={scanInterval}
            onChange={(e) => setScanInterval(e.target.value)}
            helperText="Set to 0 to disable automated scanning. Default is 3600 (1 hour)."
          />
        </Box>

        <Divider sx={{ my: 2 }} />
        
        <Box sx={{ my: 2 }}>
          <Typography variant="h6" gutterBottom>Alerting & Notifications</Typography>
          <TextField
            margin="dense"
            id="emails"
            label="Email Recipients for High-Severity Alerts"
            type="text"
            fullWidth
            variant="outlined"
            value={emails}
            onChange={(e) => setEmails(e.target.value)}
            helperText="Comma-separated list of email addresses."
          />
          <TextField
            margin="dense"
            id="slack-url"
            label="Slack Incoming Webhook URL"
            type="url"
            fullWidth
            variant="outlined"
            value={slackUrl}
            onChange={(e) => setSlackUrl(e.target.value)}
            placeholder="https://hooks.slack.com/services/..."
          />
          <TextField
            margin="dense"
            id="teams-url"
            label="MS Teams Incoming Webhook URL"
            type="url"
            fullWidth
            variant="outlined"
            value={teamsUrl}
            onChange={(e) => setTeamsUrl(e.target.value)}
            placeholder="https://your-org.webhook.office.com/..."
          />
        </Box>
      </DialogContent>
      <DialogActions sx={{ p: '0 24px 16px' }}>
        <Button onClick={handleClose}>Cancel</Button>
        <Button onClick={handleSave} variant="contained">Save and Rescan</Button>
      </DialogActions>
    </Dialog>
  );
}