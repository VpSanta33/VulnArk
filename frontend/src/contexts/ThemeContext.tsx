import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { settingsService } from '../services/settings';
import { authService } from '../services/auth';

type Theme = 'light' | 'dark' | 'system';
type Language = 'zh-CN' | 'en-US';

interface ThemeContextType {
  theme: Theme;
  language: Language;
  setTheme: (theme: Theme) => void;
  setLanguage: (language: Language) => void;
  actualTheme: 'light' | 'dark'; // The actual theme being applied (resolved from 'system')
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

interface ThemeProviderProps {
  children: ReactNode;
}

export function ThemeProvider({ children }: ThemeProviderProps) {
  const [theme, setThemeState] = useState<Theme>('system');
  const [language, setLanguageState] = useState<Language>('zh-CN');
  const [actualTheme, setActualTheme] = useState<'light' | 'dark'>('light');

  // Load theme and language from localStorage or settings
  useEffect(() => {
    const loadSettings = async () => {
      try {
        // Try to load from localStorage first for immediate application
        const savedTheme = localStorage.getItem('theme') as Theme;
        const savedLanguage = localStorage.getItem('language') as Language;

        if (savedTheme) {
          setThemeState(savedTheme);
        }
        if (savedLanguage) {
          setLanguageState(savedLanguage);
        }

        // Only load from backend if user is authenticated
        if (authService.isAuthenticated()) {
          try {
            const settings = await settingsService.getSystemSettings();
            setThemeState(settings.theme);
            setLanguageState(settings.language);

            // Save to localStorage for next time
            localStorage.setItem('theme', settings.theme);
            localStorage.setItem('language', settings.language);
          } catch (error) {
            console.error('Failed to load theme settings from backend:', error);
            // Continue with localStorage values if backend fails
          }
        }
      } catch (error) {
        console.error('Failed to load theme settings:', error);
      }
    };

    loadSettings();
  }, []);

  // Apply theme to document
  useEffect(() => {
    const applyTheme = () => {
      const root = document.documentElement;
      
      if (theme === 'system') {
        // Use system preference
        const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        const resolvedTheme = systemPrefersDark ? 'dark' : 'light';
        setActualTheme(resolvedTheme);
        
        if (resolvedTheme === 'dark') {
          root.classList.add('dark');
        } else {
          root.classList.remove('dark');
        }
      } else {
        setActualTheme(theme);
        if (theme === 'dark') {
          root.classList.add('dark');
        } else {
          root.classList.remove('dark');
        }
      }
    };

    applyTheme();

    // Listen for system theme changes when using 'system' theme
    if (theme === 'system') {
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      const handleChange = () => applyTheme();
      mediaQuery.addEventListener('change', handleChange);
      
      return () => mediaQuery.removeEventListener('change', handleChange);
    }
  }, [theme]);

  // Apply language to document
  useEffect(() => {
    document.documentElement.lang = language === 'zh-CN' ? 'zh' : 'en';
  }, [language]);

  const setTheme = (newTheme: Theme) => {
    setThemeState(newTheme);
    localStorage.setItem('theme', newTheme);
  };

  const setLanguage = (newLanguage: Language) => {
    setLanguageState(newLanguage);
    localStorage.setItem('language', newLanguage);
  };

  const value: ThemeContextType = {
    theme,
    language,
    setTheme,
    setLanguage,
    actualTheme,
  };

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
}

// Keep the existing context hook API alongside the provider.
// eslint-disable-next-line react-refresh/only-export-components
export function useTheme() {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
}
