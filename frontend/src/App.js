import React, { useState, useEffect } from "react";
import { api } from "./api";  // Import from new api.js file
import { Box, CircularProgress } from "@mui/material";
import Login from "./Login";
import Dashboard from "./Dashboard";

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("auth_token");
    if (token) {
      validateToken(token);
    } else {
      setIsLoading(false);
    }
  }, []);

  const validateToken = async (token) => {
    try {
      const response = await api.post('/api/validate-token', {});
      if (response.data.valid) {
        setIsAuthenticated(true);
      } else {
        localStorage.removeItem("auth_token");
        localStorage.removeItem("username");
      }
    } catch (error) {
      console.log("Token validation failed:", error.message);
      localStorage.removeItem("auth_token");
      localStorage.removeItem("username");
    } finally {
      setIsLoading(false);
    }
  };

  const handleLoginSuccess = (token) => {
    localStorage.setItem("auth_token", token);
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    localStorage.removeItem("auth_token");
    localStorage.removeItem("username");
    setIsAuthenticated(false);
    window.location.reload();
  };

  if (isLoading) {
    return (
      <Box sx={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)" }}>
        <CircularProgress size={60} sx={{ color: "white" }} />
      </Box>
    );
  }

  return <>{isAuthenticated ? <Dashboard onLogout={handleLogout} /> : <Login onLoginSuccess={handleLoginSuccess} />}</>;
}