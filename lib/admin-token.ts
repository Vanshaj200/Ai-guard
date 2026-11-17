// Admin token for state-changing API calls (API keys, policy, custom probes).
// Kept only in this browser's localStorage and sent as the X-Admin-Token header.
const STORAGE_KEY = 'aiguard_admin_token'

export function getAdminToken(): string {
  try {
    return localStorage.getItem(STORAGE_KEY) || ''
  } catch {
    return ''
  }
}

export function setAdminToken(token: string): void {
  try {
    if (token) localStorage.setItem(STORAGE_KEY, token)
    else localStorage.removeItem(STORAGE_KEY)
  } catch {
    // Storage unavailable (private mode); the token just won't persist
  }
}

export function adminHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const token = getAdminToken()
  return token ? { ...extra, 'X-Admin-Token': token } : { ...extra }
}

export async function errorMessage(res: Response, fallback: string): Promise<string> {
  const data = await res.json().catch(() => ({} as { detail?: string }))
  if (res.status === 401 || res.status === 403) {
    return data?.detail || 'Admin token required. Enter it on the Settings page.'
  }
  return data?.detail || fallback
}
