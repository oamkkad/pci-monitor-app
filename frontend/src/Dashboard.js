import React, { useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api";
import {
  Box,
  Chip,
  IconButton,
  Link,
  Paper,
  Snackbar,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
  Button,
  ToggleButtonGroup,
  ToggleButton,
  Collapse,
  Card,
  CardContent,
  LinearProgress,
} from "@mui/material";
import {
  PlayArrow,
  Refresh,
  Settings,
  ContentCopy,
  OpenInNew,
  Download,
  ExpandMore,
  ExpandLess,
  Security,
  Warning,
  CheckCircle,
  Error as ErrorIcon,
  Code as CodeIcon,
  Shield,
  Logout,
} from "@mui/icons-material";
import SettingsModal from "./SettingsModal";

const shortHash = (hash, head = 10, tail = 6) =>
  !hash || hash.length <= head + tail + 1 ? hash : `${hash.slice(0, head)}…${hash.slice(-tail)}`;

const filenameFromUrl = (url) => {
  if (!url) return "inline";
  try {
    const u = new URL(url);
    const parts = (u.pathname || "").split("/").filter(Boolean);
    return parts[parts.length - 1] || u.hostname || url;
  } catch {
    const parts = url.split("/").filter(Boolean);
    return parts[parts.length - 1] || url;
  }
};

function StatCard({ icon: Icon, title, value, color = "primary", trend, sx = {} }) {
  const colorMap = {
    success: { main: "#10b981", light: "rgba(16, 185, 129, 0.1)" },
    error: { main: "#ef4444", light: "rgba(239, 68, 68, 0.1)" },
    primary: { main: "#3b82f6", light: "rgba(59, 130, 246, 0.1)" },
  };
  const colors = colorMap[color] || colorMap.primary;

  return (
    <Card sx={{ height: "100%", background: `linear-gradient(135deg, ${colors.light} 0%, rgba(255,255,255,0.05) 100%)`, border: `1px solid ${colors.light}`, transition: "all 0.3s ease", "&:hover": { transform: "translateY(-4px)", boxShadow: `0 12px 24px ${colors.light}` }, ...sx }}>
      <CardContent>
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
          <Box sx={{ width: 48, height: 48, borderRadius: 2, display: "flex", alignItems: "center", justifyContent: "center", bgcolor: colors.light }}>
            <Icon sx={{ fontSize: 28, color: colors.main }} />
          </Box>
          {trend && <Chip size="small" label={trend} sx={{ bgcolor: "rgba(16, 185, 129, 0.1)", color: "#10b981", fontWeight: 600 }} />}
        </Box>
        <Typography variant="h4" sx={{ fontWeight: 700, mb: 0.5 }}>{value}</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ fontWeight: 500 }}>{title}</Typography>
      </CardContent>
    </Card>
  );
}

function ModernUrlCell({ url }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {}
  };

  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 1, maxWidth: { xs: 260, sm: 360 } }}>
      <Link href={url} target="_blank" rel="noreferrer" underline="hover" sx={{ flex: 1, color: "#3b82f6", fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", "&:hover": { color: "#2563eb" } }}>{url}</Link>
      <Box sx={{ display: "flex", gap: 0.5 }}>
        <Tooltip title={copied ? "Copied!" : "Copy URL"}>
          <IconButton size="small" onClick={handleCopy} sx={{ bgcolor: copied ? "rgba(16, 185, 129, 0.1)" : "transparent", "&:hover": { bgcolor: "rgba(59, 130, 246, 0.1)" } }}>
            <ContentCopy sx={{ fontSize: 16, color: copied ? "#10b981" : "text.secondary" }} />
          </IconButton>
        </Tooltip>
        <Tooltip title="Open">
          <IconButton size="small" href={url} target="_blank" sx={{ "&:hover": { bgcolor: "rgba(59, 130, 246, 0.1)" } }}>
            <OpenInNew sx={{ fontSize: 16, color: "text.secondary" }} />
          </IconButton>
        </Tooltip>
      </Box>
    </Box>
  );
}

function ModernScriptCell({ item }) {
  const url = item?.location;
  const isInline = item?.type === "Inline";
  const primary = isInline ? "inline" : filenameFromUrl(url);

  return (
    <Box>
      <Typography sx={{ fontWeight: 600, mb: 0.5 }}>{primary}</Typography>
      {url && !isInline && <Typography variant="caption" sx={{ color: "text.secondary", display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{url}</Typography>}
    </Box>
  );
}

function ModernTypeChip({ rawType }) {
  const config = {
    Internal: { label: "First-party", color: "#3b82f6" },
    Vendor: { label: "Third-party", color: "#8b5cf6" },
    Inline: { label: "Inline", color: "#10b981" },
  };
  const { label, color } = config[rawType] || { label: rawType, color: "#6b7280" };

  return <Chip size="small" label={label} sx={{ borderRadius: "6px", fontWeight: 600, bgcolor: `${color}1A`, color: color, border: `1px solid ${color}33` }} />;
}

function ModernAlertsTable({ rows, emptyText }) {
  return (
    <TableContainer component={Paper} sx={{ borderRadius: 2, border: "1px solid", borderColor: "divider", overflow: "hidden" }}>
      <Table>
        <TableHead>
          <TableRow sx={{ background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)" }}>
            <TableCell sx={{ fontWeight: 700, color: "white" }}>Timestamp</TableCell>
            <TableCell sx={{ fontWeight: 700, color: "white" }}>Severity</TableCell>
            <TableCell sx={{ fontWeight: 700, color: "white" }}>Type</TableCell>
            <TableCell sx={{ fontWeight: 700, color: "white" }}>Location</TableCell>
            <TableCell sx={{ fontWeight: 700, color: "white" }}>Details</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.length === 0 ? (
            <TableRow><TableCell colSpan={5} sx={{ textAlign: "center", py: 4, color: "text.secondary" }}>{emptyText}</TableCell></TableRow>
          ) : (
            rows.map((a, i) => (
              <TableRow key={`${a.id}-${i}`} sx={{ "&:hover": { bgcolor: "rgba(59, 130, 246, 0.02)" }, transition: "background-color 0.2s" }}>
                <TableCell sx={{ fontSize: "0.875rem" }}>{a.timestamp}</TableCell>
                <TableCell><Chip size="small" label={a.severity} icon={a.severity === "HIGH" ? <ErrorIcon /> : <Warning />} color={a.severity === "HIGH" ? "error" : "warning"} sx={{ fontWeight: 600 }} /></TableCell>
                <TableCell sx={{ fontWeight: 500 }}>{a.type}</TableCell>
                <TableCell><ModernUrlCell url={a.location} /></TableCell>
                <TableCell sx={{ color: "text.secondary" }}>{a.details}</TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

function CollapsibleSection({ title, icon: Icon, storageKey, defaultOpen = true, children }) {
  const [open, setOpen] = useState(() => {
    const v = localStorage.getItem(storageKey);
    return v === null ? defaultOpen : v === "1";
  });

  useEffect(() => {
    localStorage.setItem(storageKey, open ? "1" : "0");
  }, [open, storageKey]);

  return (
    <Box sx={{ mb: 3 }}>
      <Paper onClick={() => setOpen(!open)} sx={{ p: 2, display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer", borderRadius: 2, transition: "all 0.2s", background: "linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%)", "&:hover": { background: "linear-gradient(135deg, #edf2f7 0%, #e2e8f0 100%)" } }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
          {Icon && <Box sx={{ width: 40, height: 40, borderRadius: 2, display: "flex", alignItems: "center", justifyContent: "center", background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)" }}><Icon sx={{ color: "white" }} /></Box>}
          <Typography variant="h6" sx={{ fontWeight: 600 }}>{title}</Typography>
        </Box>
        <IconButton size="small">{open ? <ExpandLess /> : <ExpandMore />}</IconButton>
      </Paper>
      <Collapse in={open} timeout="auto"><Box sx={{ mt: 2 }}>{children}</Box></Collapse>
    </Box>
  );
}

export default function Dashboard({ onLogout }) {
  const [statusData, setStatusData] = useState({ overall: "N/A", last_scan: "N/A", unresolved: 0, scope: "all" });
  const [alerts, setAlerts] = useState([]);
  const [inventory, setInventory] = useState([]);
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [scope, setScope] = useState("all");
  const [loading, setLoading] = useState(false);
  const initOnce = useRef(false);

  const fetchData = async () => {
    const [s, a, i] = await Promise.all([api.get('/api/status'), api.get('/api/alerts'), api.get('/api/inventory')]);
    setStatusData(s.data);
    setScope(s.data.scope || "all");
    setAlerts(a.data);
    setInventory(i.data);
  };

  const runManualScan = async () => {
    setLoading(true);
    try {
      await api.post('/api/scan', { scope });
      await fetchData();
      setSnackbarMessage("Manual scan complete.");
    } catch {
      setSnackbarMessage("Scan failed. See alerts for details.");
    } finally {
      setLoading(false);
      setSnackbarOpen(true);
    }
  };

  const refresh = async () => {
    setLoading(true);
    await fetchData();
    setLoading(false);
    setSnackbarMessage("Refreshed.");
    setSnackbarOpen(true);
  };

  const exportToExcel = async () => {
    try {
      const res = await api.get('/api/export/inventory.xlsx', { responseType: "blob" });
      const blob = new Blob([res.data], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const stamp = new Date().toISOString().slice(0, 19).replace(/[-:T]/g, "");
      a.download = `script_inventory_${stamp}.xlsx`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      setSnackbarMessage("Excel exported.");
    } catch {
      setSnackbarMessage("Export failed.");
    } finally {
      setSnackbarOpen(true);
    }
  };

  useEffect(() => {
    if (initOnce.current) return;
    initOnce.current = true;
    (async () => { await fetchData(); })();
    const interval = setInterval(fetchData, 60_000);
    return () => clearInterval(interval);
  }, []);

  const headersItem = useMemo(() => inventory.find((s) => s.id === "headers"), [inventory]);
  const cspText = headersItem?.content?.["Content-Security-Policy"];
  const highRiskAlerts = useMemo(() => alerts.filter((a) => a.severity === "HIGH"), [alerts]);
  const cfgAlerts = useMemo(() => alerts.filter((a) => a.type.includes("Scan Failure") || a.type.includes("CSP Missing") || a.type.includes("SRI Missing")), [alerts]);

  const handleScopeChange = async (_e, val) => {
    if (!val) return;
    setScope(val);
    setLoading(true);
    try {
      await api.post('/api/scan', { scope: val });
      await fetchData();
      setSnackbarMessage(val === "entry" ? "Scope set: Entry points only" : "Scope set: All scripts");
    } catch {
      setSnackbarMessage("Failed to change scope.");
    } finally {
      setLoading(false);
      setSnackbarOpen(true);
    }
  };

  const sriCoverage = inventory.length > 1 ? Math.round((inventory.filter((s) => s.id !== "headers" && s.sri_applied).length / (inventory.length - 1)) * 100) : 0;

  return (
    <Box sx={{ minHeight: "100vh", background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)", py: 4 }}>
      {loading && <LinearProgress sx={{ position: "fixed", top: 0, left: 0, right: 0, zIndex: 9999 }} />}
      <Box sx={{ maxWidth: 1400, mx: "auto", px: 3 }}>
        <Paper elevation={3} sx={{ p: 3, mb: 3, borderRadius: 3 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <Box sx={{ width: 64, height: 64, borderRadius: 3, display: "flex", alignItems: "center", justifyContent: "center", background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)", boxShadow: "0 8px 24px rgba(102, 126, 234, 0.4)" }}>
              <Security sx={{ fontSize: 36, color: "white" }} />
            </Box>
            <Box sx={{ flex: 1 }}>
              <Typography variant="h4" sx={{ fontWeight: 700, mb: 0.5 }}>PCI DSS Compliance Dashboard</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ fontWeight: 500 }}>
                Real-time monitoring for requirements 6.4.3 & 11.6.1
                {localStorage.getItem("username") && <> • Logged in as <strong>{localStorage.getItem("username")}</strong></>}
              </Typography>
            </Box>
            <Button variant="outlined" startIcon={<Logout />} onClick={onLogout} sx={{ borderRadius: 2, textTransform: "none", fontWeight: 600, borderColor: "#ef4444", color: "#ef4444", "&:hover": { borderColor: "#dc2626", bgcolor: "rgba(239, 68, 68, 0.04)" } }}>Logout</Button>
          </Box>
          <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", alignItems: "center" }}>
            <Button variant="contained" size="large" startIcon={<PlayArrow />} onClick={runManualScan} disabled={loading} sx={{ borderRadius: 2, textTransform: "none", fontWeight: 600, px: 3, background: "linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)", boxShadow: "0 4px 12px rgba(59, 130, 246, 0.4)", "&:hover": { background: "linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)", boxShadow: "0 6px 16px rgba(59, 130, 246, 0.5)" } }}>Run Manual Scan</Button>
            <Button variant="outlined" startIcon={<Refresh />} onClick={refresh} sx={{ borderRadius: 2, textTransform: "none", fontWeight: 600 }}>Refresh</Button>
            <Button variant="outlined" startIcon={<Settings />} onClick={() => setSettingsOpen(true)} sx={{ borderRadius: 2, textTransform: "none", fontWeight: 600 }}>Settings</Button>
            <Box sx={{ flex: 1 }} />
            <Typography variant="body2" color="text.secondary">Last scan: <strong>{statusData.last_scan}</strong></Typography>
          </Box>
        </Paper>
        <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr", lg: "1fr 1fr 1fr 1fr" }, gap: 3, mb: 3 }}>
          <StatCard icon={statusData.overall === "OK" ? CheckCircle : ErrorIcon} title="Compliance Status" value={statusData.overall} color={statusData.overall === "OK" ? "success" : "error"} />
          <StatCard icon={Warning} title="Unresolved Alerts" value={statusData.unresolved} color="error" />
          <StatCard icon={CodeIcon} title="Scripts Monitored" value={inventory.filter((s) => s.id !== "headers").length} color="primary" />
          <StatCard icon={Shield} title="SRI Coverage" value={`${sriCoverage}%`} color="success" />
        </Box>
        <CollapsibleSection title="Active Tampering & Integrity Alerts" icon={ErrorIcon} storageKey="collapse_high_risk" defaultOpen={true}>
          <ModernAlertsTable rows={highRiskAlerts} emptyText="No active tampering or integrity alerts detected." />
        </CollapsibleSection>
        <CollapsibleSection title="Compliance & Configuration Alerts" icon={Warning} storageKey="collapse_cfg_alerts" defaultOpen={true}>
          <ModernAlertsTable rows={cfgAlerts} emptyText="No current configuration or scan alerts." />
        </CollapsibleSection>
        <CollapsibleSection title="Security Header Status (PCI 11.6.1)" icon={Shield} storageKey="collapse_csp" defaultOpen={true}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap" }}>
            <Chip color={cspText ? "success" : "error"} label={cspText ? "CSP Present" : "CSP Missing"} />
            {headersItem?.location && <Typography variant="body2">Page: <Link href={headersItem.location} target="_blank" rel="noreferrer">{headersItem.location}</Link></Typography>}
            {cspText && <Paper variant="outlined" sx={{ p: 2, mt: 2, width: "100%", whiteSpace: "pre-wrap", wordBreak: "break-word", bgcolor: "#f8fafc" }}>{cspText}</Paper>}
          </Box>
        </CollapsibleSection>
        <CollapsibleSection title="Script Inventory & Integrity Check (PCI 6.4.3)" icon={CodeIcon} storageKey="collapse_inventory" defaultOpen={true}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2, gap: 1, flexWrap: "wrap" }}>
            <ToggleButtonGroup size="small" exclusive value={scope} onChange={handleScopeChange} sx={{ borderRadius: 2 }}>
              <ToggleButton value="entry" sx={{ textTransform: "none", fontWeight: 600 }}>Entry Points</ToggleButton>
              <ToggleButton value="all" sx={{ textTransform: "none", fontWeight: 600 }}>All Scripts</ToggleButton>
            </ToggleButtonGroup>
            <Button variant="outlined" startIcon={<Download />} onClick={exportToExcel} sx={{ borderRadius: 2, textTransform: "none", fontWeight: 600 }}>Export to Excel</Button>
          </Box>
          <TableContainer component={Paper} sx={{ borderRadius: 2, border: "1px solid", borderColor: "divider", overflow: "hidden" }}>
            <Table>
              <TableHead>
                <TableRow sx={{ background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)" }}>
                  <TableCell sx={{ fontWeight: 700, color: "white" }}>Script</TableCell>
                  <TableCell sx={{ fontWeight: 700, color: "white" }}>Type</TableCell>
                  <TableCell sx={{ fontWeight: 700, color: "white" }}>SRI Status</TableCell>
                  <TableCell sx={{ fontWeight: 700, color: "white" }}>Hash (SHA-256)</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {inventory.filter((s) => s.id !== "headers").map((item) => (
                  <TableRow key={item.id} sx={{ "&:hover": { bgcolor: "rgba(59, 130, 246, 0.02)" }, transition: "background-color 0.2s" }}>
                    <TableCell><ModernScriptCell item={item} /></TableCell>
                    <TableCell><ModernTypeChip rawType={item.type} /></TableCell>
                    <TableCell><Chip size="small" label={item.sri_applied ? "Applied" : "Missing"} color={item.sri_applied ? "success" : "error"} sx={{ fontWeight: 600 }} /></TableCell>
                    <TableCell><Typography sx={{ fontFamily: "monospace", fontSize: "0.875rem" }}>{shortHash(item.hash)}</Typography></TableCell>
                  </TableRow>
                ))}
                {inventory.filter((s) => s.id !== "headers").length === 0 && <TableRow><TableCell colSpan={4} sx={{ textAlign: "center", py: 4 }}>No scripts found.</TableCell></TableRow>}
              </TableBody>
            </Table>
          </TableContainer>
        </CollapsibleSection>
      </Box>
      <Snackbar open={snackbarOpen} autoHideDuration={3000} onClose={() => setSnackbarOpen(false)} message={snackbarMessage} />
      <SettingsModal open={settingsOpen} handleClose={() => setSettingsOpen(false)} onConfigSave={async () => { setSettingsOpen(false); await fetchData(); setSnackbarMessage("Settings saved."); setSnackbarOpen(true); }} />
    </Box>
  );
}