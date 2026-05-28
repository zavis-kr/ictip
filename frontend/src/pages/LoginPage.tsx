import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import { useLanguage } from '../LanguageContext';
import { LANGUAGES } from '../i18n/translations';

export default function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const { lang, setLang, t } = useLanguage();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(username, password);
      navigate('/', { replace: true });
    } catch (err: any) {
      setError(err.message || t('error'));
    } finally {
      setLoading(false);
    }
  };

  const inputStyle: React.CSSProperties = {
    width: '100%', boxSizing: 'border-box', padding: '14px 18px',
    background: 'rgba(255,255,255,0.07)', border: '1.5px solid rgba(255,255,255,0.18)',
    borderRadius: 10, color: '#fff', fontSize: 16, outline: 'none',
    transition: 'border-color 0.2s',
  };

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'linear-gradient(135deg, #0a0e1a 0%, #0d1b2e 100%)',
      fontFamily: "'Noto Sans KR', sans-serif",
    }}>
      {/* 언어 선택 (우측 상단) */}
      <div style={{ position: 'fixed', top: 20, right: 20, display: 'flex', gap: 6, zIndex: 100 }}>
        {LANGUAGES.map(l => (
          <button
            key={l.code}
            onClick={() => setLang(l.code)}
            title={l.label}
            style={{
              padding: '5px 10px', borderRadius: 6, border: '1px solid',
              borderColor: lang === l.code ? '#3b82f6' : 'rgba(255,255,255,0.15)',
              background: lang === l.code ? 'rgba(59,130,246,0.2)' : 'rgba(255,255,255,0.05)',
              color: lang === l.code ? '#60a5fa' : 'rgba(255,255,255,0.6)',
              fontSize: 13, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
            }}
          >
            <span>{l.flag}</span>
            <span style={{ fontSize: 11 }}>{l.label}</span>
          </button>
        ))}
      </div>

      <div style={{
        background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.13)',
        borderRadius: 20, padding: '40px 50px', width: 'min(90vw, 480px)',
        boxShadow: '0 20px 48px rgba(0,0,0,0.7)',
      }}>
        {/* 로고 */}
        <div style={{ textAlign: 'center', marginBottom: 36 }}>
          <div style={{ fontSize: 52, fontWeight: 900, color: '#00c8ff', letterSpacing: 8, marginBottom: 10, lineHeight: 1 }}>
            ICTIP
          </div>
          <div style={{ fontSize: 15, color: 'rgba(255,255,255,0.55)', lineHeight: 1.6 }}>
            {t('loginSubtitle')}
          </div>
          <div style={{ width: 48, height: 3, background: 'linear-gradient(90deg,#00c8ff,#0066ff)', margin: '14px auto 0', borderRadius: 2 }} />
        </div>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'rgba(255,255,255,0.65)', marginBottom: 6 }}>
              {t('loginUsername')}
            </label>
            <input
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              required
              autoFocus
              style={inputStyle}
            />
          </div>

          <div style={{ marginBottom: 24 }}>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'rgba(255,255,255,0.65)', marginBottom: 6 }}>
              {t('loginPassword')}
            </label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              style={inputStyle}
            />
          </div>

          {error && (
            <div style={{
              background: 'rgba(255,80,80,0.12)', border: '1px solid rgba(255,80,80,0.3)',
              borderRadius: 8, padding: '10px 14px', marginBottom: 16,
              color: '#ff6b6b', fontSize: 13,
            }}>
              ⚠️ {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{
              width: '100%', padding: '14px', borderRadius: 10, border: 'none',
              background: loading ? 'rgba(0,200,255,0.3)' : 'linear-gradient(135deg, #00c8ff, #0066ff)',
              color: '#fff', fontSize: 16, fontWeight: 700,
              cursor: loading ? 'not-allowed' : 'pointer',
              transition: 'opacity 0.2s', letterSpacing: 2,
              boxShadow: loading ? 'none' : '0 6px 20px rgba(0,102,255,0.4)',
            }}
          >
            {loading ? t('loginLoading') : t('loginBtn')}
          </button>
        </form>

      </div>
    </div>
  );
}
