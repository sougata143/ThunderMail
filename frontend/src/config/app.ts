/**
 * Centralized application configuration.
 */
export const APP_DOMAIN =
  (import.meta as unknown as { env?: Record<string, string> }).env?.VITE_APP_DOMAIN ||
  'thundermail.sougatatech.com';

/** Helper to format or complete a local-part into a full email address */
export function formatAppEmail(localPartOrEmail: string): string {
  const trimmed = localPartOrEmail.trim().toLowerCase();
  if (!trimmed.includes('@')) {
    return `${trimmed}@${APP_DOMAIN}`;
  }
  return trimmed;
}
