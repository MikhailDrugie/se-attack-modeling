import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

// Переводы для RU
const translationsRU = {
  common: {
    login: 'Вход',
    logout: 'Выход',
    username: 'Имя пользователя',
    password: 'Пароль',
    email: 'Email',
    role: 'Роль',
    actions: 'Действия',
    create: 'Создать',
    delete: 'Удалить',
    cancel: 'Отмена',
    save: 'Сохранить',
    loading: 'Загрузка...',
    error: 'Ошибка',
    success: 'Успешно',
  },
  nav: {
    dashboard: 'Панель управления',
    scans: 'Сканирования',
    users: 'Пользователи',
    cwe: 'CWE'
  },
  auth: {
    loginTitle: 'Система анализа защищённости',
    loginButton: 'Войти',
    loginError: 'Неверное имя пользователя или пароль',
  },
  scans: {
    title: 'Сканирования',
    newScan: 'Новое сканирование',
    targetUrl: 'Целевой URL',
    // scanType: 'Тип сканирования',
    status: 'Статус',
    createdAt: 'Создано',
    vulnerabilities: 'Уязвимости',
    details: 'Детали',
    startScan: 'Запустить сканирование',
    // Статусы
    statusPending: 'Ожидание',
    statusRunning: 'Выполняется',
    statusCompleted: 'Завершено',
    statusFailed: 'Ошибка',
  },
  vulnerabilities: {
    title: 'Обнаруженные уязвимости',
    severity: 'Критичность',
    // type: 'Тип',
    name: 'Тип',  // TODO: change to some 'Type specification'
    description: 'Описание',
    affectedUrl: 'Затронутый URL',
    // recommendation: 'Рекомендация',
    // evidence: 'Доказательство',
    noVulnerabilities: 'Уязвимостей не обнаружено',
    // Уровни критичности
    severityCritical: 'Критическая',
    severityHigh: 'Высокая',
    severityMedium: 'Средняя',
    severityLow: 'Низкая',
  },
  users: {
    title: 'Управление пользователями',
    newUser: 'Новый пользователь',
    roleDev: 'Разработчик',
    roleAnalyst: 'Аналитик',
    roleAdmin: 'Администратор',
  },
};

// Переводы для EN
const translationsEN = {
  common: {
    login: 'Login',
    logout: 'Logout',
    username: 'Username',
    password: 'Password',
    email: 'Email',
    role: 'Role',
    actions: 'Actions',
    create: 'Create',
    delete: 'Delete',
    cancel: 'Cancel',
    save: 'Save',
    loading: 'Loading...',
    error: 'Error',
    success: 'Success',
  },
  nav: {
    dashboard: 'Dashboard',
    scans: 'Scans',
    users: 'Users',
    cwe: 'CWE'
  },
  auth: {
    loginTitle: 'Web Security Analysis System',
    loginButton: 'Sign In',
    loginError: 'Invalid username or password',
  },
  scans: {
    title: 'Scans',
    newScan: 'New Scan',
    targetUrl: 'Target URL',
    // scanType: 'Scan Type',
    status: 'Status',
    createdAt: 'Created',
    vulnerabilities: 'Vulnerabilities',
    details: 'Details',
    startScan: 'Start Scan',
    // Statuses
    statusPending: 'Pending',
    statusRunning: 'Running',
    statusCompleted: 'Completed',
    statusFailed: 'Failed',
  },
  vulnerabilities: {
    title: 'Detected Vulnerabilities',
    severity: 'Severity',
    // type: 'Type',
    name: 'Type', // TODO: change to some 'Type specification'
    description: 'Description',
    affectedUrl: 'Affected URL',
    // recommendation: 'Рекомендация',
    // evidence: 'Evidence',
    noVulnerabilities: 'No vulnerabilities found',
    // Severity levels
    severityCritical: 'Critical',
    severityHigh: 'High',
    severityMedium: 'Medium',
    severityLow: 'Low',
  },
  users: {
    title: 'User Management',
    newUser: 'New User',
    roleDev: 'Developer',
    roleAnalyst: 'Analyst',
    roleAdmin: 'Administrator',
  },
};

i18n
  .use(LanguageDetector)  // автоопределение языка браузера
  .use(initReactI18next)
  .init({
    resources: {
      ru: { translation: translationsRU },
      en: { translation: translationsEN },
    },
    fallbackLng: 'ru',  // по умолчанию русский
    interpolation: {
      escapeValue: false,
    },
  });

export default i18n;
