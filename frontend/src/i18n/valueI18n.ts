/**
 * DB에 저장된 한국어 값(심각도, 위협유형, 국가명 등)을 번역 키로 매핑.
 * value는 API 전송 시 한국어 유지, UI 표시만 t()로 번역.
 */
import { TKey } from './translations';

export const SEVERITY_KEY: Record<string, TKey> = {
  '긴급': 'sevCritical',
  '높음': 'sevHigh',
  '중간': 'sevMedium',
  '낮음': 'sevLow',
};

export const RISK_KEY: Record<string, TKey> = {
  '위험': 'riskCritical',
  '경고': 'riskHigh',
  '주의': 'riskMedium',
  '정보': 'riskInfo',
};

export const THREAT_TYPE_KEY: Record<string, TKey> = {
  '악성코드/랜섬웨어':  'ttMalware',
  '랜섬웨어':           'ttRansomware',
  'APT/국가지원':       'ttAPT',
  'APT/스파이웨어':     'ttAPT',
  '피싱/소셜엔지니어링':'ttPhishing',
  '피싱/소셜엔지니어':  'ttPhishing',
  '공급망공격':          'ttSupplyChain',
  '취약점/익스플로잇':  'ttVuln',
  'C2/봇넷':            'ttC2',
  '봇넷/C&C':           'ttC2',
  'DDoS/서비스거부':    'ttDDoS',
  '기타':               'ttOther',
};

export const COUNTRY_KEY: Record<string, TKey> = {
  KR: 'countryKR', US: 'countryUS', CN: 'countryCN', RU: 'countryRU',
  JP: 'countryJP', DE: 'countryDE', GB: 'countryGB', FR: 'countryFR',
  IR: 'countryIR', KP: 'countryKP', UA: 'countryUA', IN: 'countryIN',
};

export const TREND_KEY: Record<string, TKey> = {
  '상승': 'trendUp',
  '하락': 'trendDown',
  '안정': 'trendStable',
};

// 드롭다운용 배열 - value는 DB 값(한국어), labelKey는 번역 키
export const SEVERITY_OPTIONS: { value: string; labelKey: TKey }[] = [
  { value: '긴급', labelKey: 'sevCritical' },
  { value: '높음', labelKey: 'sevHigh' },
  { value: '중간', labelKey: 'sevMedium' },
  { value: '낮음', labelKey: 'sevLow' },
];

export const THREAT_TYPE_OPTIONS: { value: string; labelKey: TKey }[] = [
  { value: '악성코드/랜섬웨어',   labelKey: 'ttMalware' },
  { value: '랜섬웨어',            labelKey: 'ttRansomware' },
  { value: 'APT/국가지원',        labelKey: 'ttAPT' },
  { value: '피싱/소셜엔지니어링', labelKey: 'ttPhishing' },
  { value: '공급망공격',          labelKey: 'ttSupplyChain' },
  { value: '취약점/익스플로잇',   labelKey: 'ttVuln' },
  { value: 'C2/봇넷',             labelKey: 'ttC2' },
  { value: 'DDoS/서비스거부',     labelKey: 'ttDDoS' },
  { value: '기타',                labelKey: 'ttOther' },
];

export const SUBMIT_THREAT_TYPE_OPTIONS: { value: string; labelKey: TKey }[] = [
  { value: '랜섬웨어',            labelKey: 'ttRansomware' },
  { value: 'APT/국가지원',        labelKey: 'ttAPT' },
  { value: '피싱/소셜엔지니어링', labelKey: 'ttPhishing' },
  { value: '공급망공격',          labelKey: 'ttSupplyChain' },
  { value: '기타',                labelKey: 'ttOther' },
];

export const COUNTRY_OPTIONS: { code: string; nameKey: TKey }[] = [
  { code: 'KR', nameKey: 'countryKR' },
  { code: 'US', nameKey: 'countryUS' },
  { code: 'CN', nameKey: 'countryCN' },
  { code: 'RU', nameKey: 'countryRU' },
  { code: 'JP', nameKey: 'countryJP' },
  { code: 'DE', nameKey: 'countryDE' },
  { code: 'GB', nameKey: 'countryGB' },
  { code: 'FR', nameKey: 'countryFR' },
  { code: 'IR', nameKey: 'countryIR' },
  { code: 'KP', nameKey: 'countryKP' },
  { code: 'UA', nameKey: 'countryUA' },
  { code: 'IN', nameKey: 'countryIN' },
];
