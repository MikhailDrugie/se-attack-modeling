export const UserRole = {
  DEV: 1,
  ANALYST: 2,
  ADMIN: 3,
} as const;

export type UserRole = typeof UserRole[keyof typeof UserRole];

export const ScanStatus = {
  PENDING: 1,
  RUNNING: 2,
  COMPLETED: 3,
  FAILED: 4,
} as const;

export type ScanStatus = typeof ScanStatus[keyof typeof ScanStatus];

export const VulnerabilitySeverity = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
} as const;

export type VulnerabilitySeverity = typeof VulnerabilitySeverity[keyof typeof VulnerabilitySeverity];

// Маппинги для отображения (i18n ключи)
export const UserRoleLabels: Record<UserRole, string> = {
  [UserRole.DEV]: 'users.roleDev',
  [UserRole.ANALYST]: 'users.roleAnalyst',
  [UserRole.ADMIN]: 'users.roleAdmin',
};

export const ScanStatusLabels: Record<ScanStatus, string> = {
  [ScanStatus.PENDING]: 'scans.statusPending',
  [ScanStatus.RUNNING]: 'scans.statusRunning',
  [ScanStatus.COMPLETED]: 'scans.statusCompleted',
  [ScanStatus.FAILED]: 'scans.statusFailed',
};

export const VulnerabilitySeverityLabels: Record<VulnerabilitySeverity, string> = {
  [VulnerabilitySeverity.LOW]: 'vulnerabilities.severityLow',
  [VulnerabilitySeverity.MEDIUM]: 'vulnerabilities.severityMedium',
  [VulnerabilitySeverity.HIGH]: 'vulnerabilities.severityHigh',
  [VulnerabilitySeverity.CRITICAL]: 'vulnerabilities.severityCritical',
};

// Цвета для отображения критичности
export const SeverityColors: Record<VulnerabilitySeverity, 'error' | 'warning' | 'info' | 'success'> = {
  [VulnerabilitySeverity.CRITICAL]: 'error',
  [VulnerabilitySeverity.HIGH]: 'error',
  [VulnerabilitySeverity.MEDIUM]: 'warning',
  [VulnerabilitySeverity.LOW]: 'info',
};

export interface User {
  id: number;
  username: string;
  role: UserRole;
  created_at: string;
  updated_at: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
}

export interface CWE {
  id: string;
  name: string;
  description: string;
  extended_description?: string;
  severity: string;
  remediation: string;
  references?: string[];
  owasp_mapping?: string[];
}

export interface Vulnerability { // TODO: нет type (их на данный момент в бекенде 8, тоже хранятся в числах)
  id: number;
  scan_id: number;
  name: string;
  severity: VulnerabilitySeverity;
  url_path: string;
  description?: string;
//   evidence?: string; // TODO: evidence у нас пока нет
  cwe_id?: string;
  cwe?: CWE;
}

export interface Scan {
  id: number;
  target_url: string;
  status: ScanStatus;
//   scan_type: string; // TODO: пока что нет "типа сканирования"
  created_at: string;
  completed_at?: string;
  user_id: number;
  vulnerabilities?: Vulnerability[];
  vulnerabilities_amount?: number;
}
