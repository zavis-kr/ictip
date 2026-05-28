import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom';
import DashboardPage from './pages/DashboardPage';
import ThreatSubmitPage from './pages/ThreatSubmitPage';
import ThreatManagePage from './pages/ThreatManagePage';
import ThreatDetailPage from './pages/ThreatDetailPage';
import SharePage from './pages/SharePage';
import LoginPage from './pages/LoginPage';
import IntelligencePage from './pages/IntelligencePage';
import { AuthProvider, useAuth } from './AuthContext';
import { LanguageProvider, useLanguage } from './LanguageContext';
import { LANGUAGES } from './i18n/translations';
import './App.css';

const ROLE_KEY: Record<string, 'roleAdmin' | 'roleAnalyst' | 'roleViewer'> = {
  admin: 'roleAdmin', analyst: 'roleAnalyst', viewer: 'roleViewer',
};

function Sidebar() {
  const { isAuthenticated, user, logout } = useAuth();
  const { lang, setLang, t } = useLanguage();
  const [langOpen, setLangOpen] = useState(false);

  const NAV_ITEMS = [
    { to: '/',            key: 'navDashboard'    as const, icon: '📊', end: true  },
    { to: '/submit',      key: 'navSubmit'       as const, icon: '➕', end: false },
    { to: '/threats',     key: 'navThreats'      as const, icon: '🛡', end: false },
    { to: '/share',       key: 'navShare'        as const, icon: '🌐', end: false },
    { to: '/intelligence',key: 'navIntelligence' as const, icon: '🧠', end: false },
  ];

  if (!isAuthenticated) return null;

  const currentLang = LANGUAGES.find(l => l.code === lang);

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <span className="sidebar-logo">ICTIP</span>
        <span className="sidebar-subtitle" style={{ whiteSpace: 'pre-line' }}>
          {t('sidebarSubtitle')}
        </span>
      </div>

      <nav className="sidebar-nav">
        {NAV_ITEMS.map(({ to, key, icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <span className="sidebar-icon">{icon}</span>
            <span className="sidebar-label">{t(key)}</span>
          </NavLink>
        ))}
      </nav>

      <div style={{ marginTop: 'auto', padding: '12px', borderTop: '1px solid rgba(255,255,255,0.08)', display: 'flex', flexDirection: 'column', gap: 8 }}>

        {/* 언어 선택기 */}
        <div style={{ position: 'relative' }}>
          <button
            onClick={() => setLangOpen(v => !v)}
            style={{
              width: '100%', padding: '7px 10px', borderRadius: 6,
              border: '1px solid rgba(255,255,255,0.18)',
              background: langOpen ? 'rgba(255,255,255,0.1)' : 'rgba(255,255,255,0.05)',
              color: 'rgba(255,255,255,0.75)', fontSize: 12, cursor: 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6,
            }}
          >
            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 15 }}>{currentLang?.flag}</span>
              <span>{currentLang?.label}</span>
            </span>
            <span style={{ fontSize: 10, opacity: 0.6 }}>{langOpen ? '▲' : '▼'}</span>
          </button>

          {langOpen && (
            <div style={{
              position: 'absolute', bottom: '100%', left: 0, right: 0, marginBottom: 4,
              background: '#1e293b', border: '1px solid #334155', borderRadius: 8,
              overflow: 'hidden', zIndex: 100,
              boxShadow: '0 -8px 24px rgba(0,0,0,0.4)',
            }}>
              {LANGUAGES.map(l => (
                <button
                  key={l.code}
                  onClick={() => { setLang(l.code); setLangOpen(false); }}
                  style={{
                    width: '100%', padding: '9px 12px', border: 'none',
                    background: lang === l.code ? 'rgba(59,130,246,0.2)' : 'transparent',
                    color: lang === l.code ? '#60a5fa' : 'rgba(255,255,255,0.7)',
                    fontSize: 13, cursor: 'pointer', textAlign: 'left',
                    display: 'flex', alignItems: 'center', gap: 8,
                    borderLeft: lang === l.code ? '2px solid #3b82f6' : '2px solid transparent',
                  }}
                >
                  <span style={{ fontSize: 16 }}>{l.flag}</span>
                  <span>{l.label}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* 사용자 정보 */}
        <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)' }}>
          {t(ROLE_KEY[user?.role ?? ''] ?? 'roleViewer')}
        </div>
        <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.8)', fontWeight: 600 }}>
          {user?.username}
        </div>
        <button
          onClick={logout}
          style={{
            width: '100%', padding: '7px', borderRadius: 6,
            border: '1px solid rgba(255,255,255,0.15)',
            background: 'rgba(255,255,255,0.05)', color: 'rgba(255,255,255,0.55)',
            fontSize: 12, cursor: 'pointer',
          }}
        >
          {t('logout')}
        </button>
      </div>
    </aside>
  );
}

function AppShell() {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  return (
    <div className="app">
      <div className="app-inner">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/submit" element={<ThreatSubmitPage />} />
            <Route path="/threats" element={<ThreatManagePage />} />
            <Route path="/threats/:id" element={<ThreatDetailPage />} />
            <Route path="/share" element={<SharePage />} />
            <Route path="/intelligence" element={<IntelligencePage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <LanguageProvider>
        <AuthProvider>
          <AppShell />
        </AuthProvider>
      </LanguageProvider>
    </BrowserRouter>
  );
}
