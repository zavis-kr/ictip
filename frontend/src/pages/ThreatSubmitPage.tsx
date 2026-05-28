import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api';
import { useLanguage } from '../LanguageContext';
import { SEVERITY_OPTIONS, SUBMIT_THREAT_TYPE_OPTIONS, COUNTRY_OPTIONS } from '../i18n/valueI18n';
import './pages.css';

const IOC_TYPES = ['IP', 'Domain', 'URL', 'Hash-MD5', 'Hash-SHA256', 'Email', 'CVE', 'Other'];

const TLP_OPTION_VALUES = [
  { value: 'WHITE', label: 'TLP:WHITE', descKey: 'tlpWhiteDesc', color: '#e2e8f0' },
  { value: 'GREEN', label: 'TLP:GREEN', descKey: 'tlpGreenDesc', color: '#22c55e' },
  { value: 'AMBER', label: 'TLP:AMBER', descKey: 'tlpAmberDesc', color: '#f59e0b' },
  { value: 'RED',   label: 'TLP:RED',   descKey: 'tlpRedDesc',   color: '#ef4444' },
] as const;

const INITIAL = {
  title: '',
  severity: '중간',
  threat_type: '기타',
  source: 'internal',
  ioc_value: '',
  ioc_type: 'IP',
  country_code: '',
  actor_tag: '',
  description: '',
  ioc_count: 1,
  tlp_level: 'WHITE',
};

export default function ThreatSubmitPage() {
  const navigate = useNavigate();
  const { t } = useLanguage();
  const [form, setForm] = useState(INITIAL);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const set = (field: string, value: string | number) =>
    setForm((prev) => ({ ...prev, [field]: value }));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.title.trim()) { setError(t('titleRequired')); return; }
    setSubmitting(true);
    setError('');
    try {
      const threat = await api.createThreat({
        ...form,
        ioc_value: form.ioc_value || undefined,
        ioc_type: form.ioc_value ? form.ioc_type : undefined,
        country_code: form.country_code || undefined,
        actor_tag: form.actor_tag || undefined,
        description: form.description || undefined,
      });
      setSuccess(`#${threat.id} ${t('submitSuccessMsg')}`);
      setTimeout(() => navigate(`/threats/${threat.id}`), 1500);
    } catch (e: any) {
      setError(e.message || t('submitError'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h2 className="page-title">{t('submitTitle')}</h2>
        <p className="page-desc">{t('submitDesc')}</p>
      </div>

      <div className="form-card">
        {error && <div className="alert alert-error">{error}</div>}
        {success && <div className="alert alert-success">{success}</div>}

        <form onSubmit={handleSubmit} className="threat-form">
          {/* 기본 정보 */}
          <div className="form-section">
            <h3 className="form-section-title">{t('sectionBasicInfo')}</h3>
            <div className="form-row full">
              <label className="form-label">{t('fieldTitle')}</label>
              <input
                className="form-input"
                type="text"
                placeholder={t('titlePlaceholder')}
                value={form.title}
                onChange={(e) => set('title', e.target.value)}
              />
            </div>

            <div className="form-row-group">
              <div className="form-row">
                <label className="form-label">{t('fieldSeverity')}</label>
                <select className="form-select" value={form.severity} onChange={(e) => set('severity', e.target.value)}>
                  {SEVERITY_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>{t(o.labelKey)}</option>
                  ))}
                </select>
              </div>
              <div className="form-row">
                <label className="form-label">{t('fieldType')}</label>
                <select className="form-select" value={form.threat_type} onChange={(e) => set('threat_type', e.target.value)}>
                  {SUBMIT_THREAT_TYPE_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>{t(o.labelKey)}</option>
                  ))}
                </select>
              </div>
              <div className="form-row">
                <label className="form-label">{t('fieldTLPLevel')}</label>
                <select className="form-select" value={form.tlp_level} onChange={(e) => set('tlp_level', e.target.value)}>
                  {TLP_OPTION_VALUES.map((o) => (
                    <option key={o.value} value={o.value}>{o.label} — {t(o.descKey as any)}</option>
                  ))}
                </select>
              </div>
              <div className="form-row">
                <label className="form-label">{t('fieldSource')}</label>
                <input
                  className="form-input"
                  type="text"
                  placeholder="internal, ThreatFox, ..."
                  value={form.source}
                  onChange={(e) => set('source', e.target.value)}
                />
              </div>
            </div>
          </div>

          {/* IOC 정보 */}
          <div className="form-section">
            <h3 className="form-section-title">{t('sectionIOC')}</h3>
            <div className="form-row-group">
              <div className="form-row">
                <label className="form-label">{t('fieldIOCType')}</label>
                <select className="form-select" value={form.ioc_type} onChange={(e) => set('ioc_type', e.target.value)}>
                  {IOC_TYPES.map((t) => <option key={t}>{t}</option>)}
                </select>
              </div>
              <div className="form-row" style={{ flex: 2 }}>
                <label className="form-label">{t('fieldIOCValue')}</label>
                <input
                  className="form-input"
                  type="text"
                  placeholder="192.168.1.1 / evil.com / abc123... "
                  value={form.ioc_value}
                  onChange={(e) => set('ioc_value', e.target.value)}
                />
              </div>
              <div className="form-row">
                <label className="form-label">{t('fieldIOCCount')}</label>
                <input
                  className="form-input"
                  type="number"
                  min={1}
                  value={form.ioc_count}
                  onChange={(e) => set('ioc_count', parseInt(e.target.value) || 1)}
                />
              </div>
            </div>
          </div>

          {/* 귀속 정보 */}
          <div className="form-section">
            <h3 className="form-section-title">{t('sectionAttribution')}</h3>
            <div className="form-row-group">
              <div className="form-row">
                <label className="form-label">{t('fieldCountry')}</label>
                <select className="form-select" value={form.country_code} onChange={(e) => set('country_code', e.target.value)}>
                  <option value="">{t('unknownCountry')}</option>
                  {COUNTRY_OPTIONS.map((c) => (
                    <option key={c.code} value={c.code}>{t(c.nameKey)} ({c.code})</option>
                  ))}
                </select>
              </div>
              <div className="form-row" style={{ flex: 2 }}>
                <label className="form-label">{t('fieldActor')}</label>
                <input
                  className="form-input"
                  type="text"
                  placeholder={t('actorPlaceholder')}
                  value={form.actor_tag}
                  onChange={(e) => set('actor_tag', e.target.value)}
                />
              </div>
            </div>
          </div>

          {/* 상세 설명 */}
          <div className="form-section">
            <h3 className="form-section-title">{t('sectionDescription')}</h3>
            <div className="form-row full">
              <label className="form-label">{t('fieldThreatDesc')}</label>
              <textarea
                className="form-textarea"
                rows={5}
                placeholder={t('descPlaceholder')}
                value={form.description}
                onChange={(e) => set('description', e.target.value)}
              />
            </div>
          </div>

          <div className="form-actions">
            <button type="button" className="btn btn-secondary" onClick={() => setForm(INITIAL)}>
              {t('btnReset')}
            </button>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? t('submitting') : t('submitTitle')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
