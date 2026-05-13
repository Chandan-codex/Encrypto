import React, { useState, useEffect } from 'react';
import { auth, googleProvider } from './firebase';
import { signInWithPopup, signOut, onAuthStateChanged } from 'firebase/auth';
import axios from 'axios';
import { Shield, Lock, Unlock, LogOut, Copy, Check, AlertCircle } from 'lucide-react';
import './App.css';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:5000/api';

function App() {
  const [user, setUser] = useState(null);
  const [mode, setMode] = useState('encrypt');
  const [input, setInput] = useState('');
  const [result, setResult] = useState('');
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (u) => {
      setUser(u);
    });
    return () => unsubscribe();
  }, []);

  const handleLogin = async () => {
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (err) {
      alert("Please update your Firebase config in src/firebase.js");
    }
  };

  const handleLogout = () => signOut(auth);

  const validateInput = (val) => {
    if (mode === 'decrypt') {
      const colons = val.split(':').length - 1;
      if (colons < 2) {
        return "Invalid Payload format. Expected Key:IV:Ciphertext";
      }
    }
    return '';
  };

  const handleProcess = async () => {
    if (!input) return;

    // Sanitize input: Remove all spaces if we are in decrypt mode
    let sanitizedInput = input;
    if (mode === 'decrypt') {
      sanitizedInput = input.replace(/\s+/g, '');
    }

    const err = validateInput(sanitizedInput);
    if (err) {
      setError(err);
      setTimeout(() => setError(''), 3000);
      return;
    }

    setLoading(true);
    setResult('');
    setError('');

    try {
      if (mode === 'encrypt') {
        const res = await axios.post(`${API_BASE}/encrypt`, { message: sanitizedInput });
        setResult(res.data.payload);
      } else {
        const res = await axios.post(`${API_BASE}/decrypt`, { payload: sanitizedInput });
        setResult(res.data.message);
      }
    } catch (err) {
      setError("Decryption failed. Ensure the keys and payload match.");
      setTimeout(() => setError(''), 4000);
    }
    setLoading(false);
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(result);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!user) {
    return (
      <div className="app-container login-bg">
        <div className="glass-card auth-card">
          <div className="auth-header">
            <div className="logo-icon">
              <Shield size={32} color="#ffffff" fill="rgba(255,255,255,0.1)" />
            </div>
            <h1 className="title">ENCRYPTO</h1>
            <p className="subtitle">Military-grade hybrid encryption for the modern web.</p>
            <h2 className="auth-title" style={{ fontSize: '1.2rem', marginTop: '20px' }}>Secure Access</h2>
          </div>

          <button className="btn-google-modern" onClick={handleLogin}>
            <div className="google-icon-box">
              <img src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg" width="18" alt="google" />
            </div>
            Sign in with Google
          </button>

          <div className="divider">
            <span>SECURE ENCLAVE ACTIVE</span>
          </div>

          <div className="footer-tag">
            <div className="dot"></div>
            End-to-End Encrypted
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app-container main-bg">
      <div className="glass-card main-card">
        <div className="header-nav">
          <div className="brand-box">
            <Shield size={20} color="#7c3aed" />
            <span className="brand-text">ENCRYPTO</span>
          </div>
          <button onClick={handleLogout} className="logout-btn">
            <LogOut size={18} />
          </button>
        </div>

        <h1 className="welcome-text">Welcome, <span className="highlight">{user.displayName.split(' ')[0]}</span></h1>
        <p className="subtitle" style={{ textAlign: 'center', marginTop: '-15px', marginBottom: '25px' }}>
          Secure your thoughts instantly.
        </p>

        <div className="mode-selector">
          <button
            className={`mode-btn ${mode === 'encrypt' ? 'active' : ''}`}
            onClick={() => { setMode('encrypt'); setInput(''); setResult(''); setError(''); }}
          >
            <Lock size={16} /> Encrypt
          </button>
          <button
            className={`mode-btn ${mode === 'decrypt' ? 'active' : ''}`}
            onClick={() => { setMode('decrypt'); setInput(''); setResult(''); setError(''); }}
          >
            <Unlock size={16} /> Decrypt
          </button>
        </div>

        <div className="input-box">
          <textarea
            placeholder={mode === 'encrypt' ? "Enter message to secure..." : "Enter payload to decrypt..."}
            value={input}
            onChange={(e) => { setInput(e.target.value); setError(''); }}
            rows={3}
          />
        </div>

        {error && (
          <div className="error-flash">
            <AlertCircle size={16} />
            {error}
          </div>
        )}

        <button className="action-btn" onClick={handleProcess} disabled={loading}>
          {loading ? (
            <div className="loader"></div>
          ) : (
            <>
              {mode === 'encrypt' ? <Lock size={18} /> : <Unlock size={18} />}
              {mode === 'encrypt' ? 'Encrypt Message' : 'Decrypt Payload'}
            </>
          )}
        </button>

        {result && (
          <div className="result-container">
            <div className="result-header">
              {mode === 'encrypt' ? 'Encrypted Payload:' : 'Decrypted Message:'}
            </div>
            <div className={`result-content ${mode === 'decrypt' ? 'plaintext' : 'payload'}`}>
              <strong>{result}</strong>
            </div>
            <button className="copy-action" onClick={copyToClipboard}>
              {copied ? <Check size={16} /> : <Copy size={16} />}
              {copied ? 'Copied to Clipboard' : 'Copy Result'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
