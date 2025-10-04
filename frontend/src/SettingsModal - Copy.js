import React, { useState, useEffect } from "react";
import axios from "axios";
import {
  Modal, Box, Typography, TextField, Button,
  CircularProgress, Alert, Divider
} from "@mui/material";
import { Save } from "@mui/icons-material";

const style = {
  position: "absolute",
  top: "50%",
  left: "50%",
  transform: "translate(-50%, -50%)",
  width: 600,
  bgcolor: "background.paper",
  boxShadow: 24,
  p: 4,
  borderRadius: 2
};

export default function SettingsModal({ open, handleClose, onConfigSave, apiBaseUrl }) {
  const [url, setUrl] = useState("");
  const [emails, setEmails] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [messageSeverity, setMessageSeverity] = useState("info");

  useEffect(() => {
    if (open) {
      setLoading(true);
      setMessage("");
      axios.get(`${apiBaseUrl}/api/config`)
        .then(res => {
          setUrl(res.data.url || "");
          setEmails((res.data.email_recipients || []).join(", "));
        })
        .catch(() => {
          setMessage("Failed to load configuration.");
          setMessageSeverity("error");
        })
        .finally(() => setLoading(false));
    }
  }, [open, apiBaseUrl]);

  const handleSave = async () => {
    setLoading(true);
    setMessage("");
    try {
      await axios.post(`${apiBaseUrl}/api/config`, {
        url,
        emails
      });
      setMessage("Configuration saved successfully!");
      setMessageSeverity("success");
      onConfigSave && onConfigSave();
    } catch (err) {
      setMessage("Failed to save configuration.");
      setMessageSeverity("error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal open={open} onClose={handleClose}>
      <Box sx={style}>
        <Typography variant="h5" component="h2" gutterBottom>
          <Save sx={{ mr: 1 }} /> Application Settings
        </Typography>
        <Divider sx={{ mb: 3 }} />

        {message && (
          <Alert severity={messageSeverity} sx={{ mb: 2 }}>
            {message}
          </Alert>
        )}

        <Typography variant="h6" sx={{ mt: 2, mb: 1 }}>
          Payment Page URL (PCI 6.4.3 & 11.6.1 Scope)
        </Typography>
        <TextField
          fullWidth
          label="URL (e.g., https://mystore.com/checkout)"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          margin="normal"
          disabled={loading}
          helperText="This must be the exact payment page where card data is entered."
        />

        <Typography variant="h6" sx={{ mt: 3, mb: 1 }}>
          Alert Email Recipients (PCI 11.6.1 Personnel)
        </Typography>
        <TextField
          fullWidth
          label="Email Addresses"
          value={emails}
          onChange={(e) => setEmails(e.target.value)}
          margin="normal"
          disabled={loading}
          helperText="Enter multiple addresses separated by commas (e.g., team@example.com, auditor@example.com)"
        />

        <Box sx={{ display: "flex", justifyContent: "flex-end", mt: 4 }}>
          <Button onClick={handleClose} sx={{ mr: 2 }} disabled={loading}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleSave}
            startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <Save />}
            disabled={loading || !url}
          >
            Save Configuration
          </Button>
        </Box>
      </Box>
    </Modal>
  );
}
