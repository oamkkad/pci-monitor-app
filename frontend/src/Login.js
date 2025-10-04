import React, { useState } from "react";
import { api } from "./api";
import {
  Box,
  Button,
  Card,
  CardContent,
  TextField,
  Typography,
  Alert,
  InputAdornment,
  IconButton,
  CircularProgress,
} from "@mui/material";
import {
  Visibility,
  VisibilityOff,
  Security,
  Lock,
  Person,
} from "@mui/icons-material";

export default function Login({ onLoginSuccess }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const response = await api.post('/api/login', {
        username: username.trim(),
        password: password.trim(),
      });

      if (response.data.success) {
        localStorage.setItem("auth_token", response.data.token);
        localStorage.setItem("username", username);
        onLoginSuccess(response.data.token);
      } else {
        setError(response.data.message || "Login failed");
      }
    } catch (err) {
      console.error("Login error:", err);
      setError(err.response?.data?.message || "Invalid credentials. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box
      sx={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
        position: "relative",
        overflow: "hidden",
        "&::before": {
          content: '""',
          position: "absolute",
          top: "-50%",
          right: "-50%",
          width: "100%",
          height: "100%",
          background: "radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%)",
          animation: "pulse 15s ease-in-out infinite",
        },
        "@keyframes pulse": {
          "0%, 100%": { transform: "scale(1)", opacity: 0.5 },
          "50%": { transform: "scale(1.5)", opacity: 0.3 },
        },
      }}
    >
      <Card
        elevation={24}
        sx={{
          maxWidth: 450,
          width: "100%",
          mx: 2,
          borderRadius: 4,
          overflow: "hidden",
          position: "relative",
          zIndex: 1,
          animation: "slideUp 0.6s ease",
          "@keyframes slideUp": {
            from: { opacity: 0, transform: "translateY(30px)" },
            to: { opacity: 1, transform: "translateY(0)" },
          },
        }}
      >
        <Box
          sx={{
            background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
            py: 4,
            px: 3,
            textAlign: "center",
            position: "relative",
            "&::after": {
              content: '""',
              position: "absolute",
              bottom: -1,
              left: 0,
              right: 0,
              height: "20px",
              background: "white",
              borderRadius: "50% 50% 0 0 / 100% 100% 0 0",
            },
          }}
        >
          <Box
            sx={{
              width: 80,
              height: 80,
              borderRadius: 3,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              bgcolor: "rgba(255, 255, 255, 0.2)",
              backdropFilter: "blur(10px)",
              mx: "auto",
              mb: 2,
              boxShadow: "0 8px 32px rgba(0, 0, 0, 0.1)",
            }}
          >
            <Security sx={{ fontSize: 48, color: "white" }} />
          </Box>
          <Typography variant="h4" sx={{ fontWeight: 800, color: "white", mb: 0.5 }}>
            PCI DSS Monitor
          </Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.9)" }}>
            Compliance Dashboard Login
          </Typography>
        </Box>

        <CardContent sx={{ p: 4, pt: 3 }}>
          <Typography
            variant="h6"
            sx={{ mb: 3, fontWeight: 600, textAlign: "center", color: "text.primary" }}
          >
            Sign in to continue
          </Typography>

          {error && (
            <Alert
              severity="error"
              sx={{
                mb: 3,
                borderRadius: 2,
                animation: "shake 0.5s",
                "@keyframes shake": {
                  "0%, 100%": { transform: "translateX(0)" },
                  "25%": { transform: "translateX(-10px)" },
                  "75%": { transform: "translateX(10px)" },
                },
              }}
            >
              {error}
            </Alert>
          )}

          <form onSubmit={handleSubmit}>
            <TextField
              fullWidth
              label="Username"
              variant="outlined"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              disabled={loading}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Person sx={{ color: "action.active" }} />
                  </InputAdornment>
                ),
              }}
              sx={{
                mb: 2.5,
                "& .MuiOutlinedInput-root": {
                  borderRadius: 2,
                  transition: "all 0.3s",
                  "&:hover": {
                    boxShadow: "0 4px 12px rgba(102, 126, 234, 0.15)",
                  },
                  "&.Mui-focused": {
                    boxShadow: "0 4px 12px rgba(102, 126, 234, 0.25)",
                  },
                },
              }}
            />

            <TextField
              fullWidth
              label="Password"
              type={showPassword ? "text" : "password"}
              variant="outlined"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={loading}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Lock sx={{ color: "action.active" }} />
                  </InputAdornment>
                ),
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton
                      onClick={() => setShowPassword(!showPassword)}
                      edge="end"
                      disabled={loading}
                    >
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
              sx={{
                mb: 3,
                "& .MuiOutlinedInput-root": {
                  borderRadius: 2,
                  transition: "all 0.3s",
                  "&:hover": {
                    boxShadow: "0 4px 12px rgba(102, 126, 234, 0.15)",
                  },
                  "&.Mui-focused": {
                    boxShadow: "0 4px 12px rgba(102, 126, 234, 0.25)",
                  },
                },
              }}
            />

            <Button
              type="submit"
              fullWidth
              variant="contained"
              size="large"
              disabled={loading}
              sx={{
                py: 1.5,
                borderRadius: 2,
                textTransform: "none",
                fontSize: "1.1rem",
                fontWeight: 700,
                background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
                boxShadow: "0 4px 12px rgba(102, 126, 234, 0.4)",
                transition: "all 0.3s",
                "&:hover": {
                  background: "linear-gradient(135deg, #5568d3 0%, #6a3f8f 100%)",
                  boxShadow: "0 6px 20px rgba(102, 126, 234, 0.6)",
                  transform: "translateY(-2px)",
                },
                "&:disabled": {
                  background: "linear-gradient(135deg, #a0a0a0 0%, #808080 100%)",
                },
              }}
            >
              {loading ? (
                <CircularProgress size={24} sx={{ color: "white" }} />
              ) : (
                "Sign In"
              )}
            </Button>
          </form>

          <Box sx={{ mt: 3, textAlign: "center" }}>
            <Typography variant="caption" color="text.secondary">
              Default credentials: admin / admin
            </Typography>
          </Box>
        </CardContent>

        <Box
          sx={{
            height: 8,
            background: "linear-gradient(90deg, #667eea 0%, #764ba2 50%, #667eea 100%)",
            backgroundSize: "200% 100%",
            animation: "gradient 3s ease infinite",
            "@keyframes gradient": {
              "0%, 100%": { backgroundPosition: "0% 50%" },
              "50%": { backgroundPosition: "100% 50%" },
            },
          }}
        />
      </Card>
    </Box>
  );
}