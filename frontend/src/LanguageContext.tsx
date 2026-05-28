import React, { createContext, useContext, useState, useCallback } from 'react';
import { LangCode, getT, TKey, LOCALE_MAP } from './i18n/translations';

interface LanguageContextType {
  lang: LangCode;
  locale: string;
  setLang: (lang: LangCode) => void;
  t: (key: TKey | string) => string;
}

const LanguageContext = createContext<LanguageContextType>({
  lang: 'ko',
  locale: 'ko-KR',
  setLang: () => {},
  t: (key) => String(key),
});

export function LanguageProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<LangCode>(() => {
    return (localStorage.getItem('ictip_lang') as LangCode) ?? 'ko';
  });

  const setLang = useCallback((l: LangCode) => {
    localStorage.setItem('ictip_lang', l);
    setLangState(l);
  }, []);

  const locale = LOCALE_MAP[lang];
  const t = useCallback((key: TKey | string) => getT(lang)(key), [lang]);

  return (
    <LanguageContext.Provider value={{ lang, locale, setLang, t }}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage() {
  return useContext(LanguageContext);
}
