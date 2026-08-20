/**
 * AuthBadge.tsx
 *
 * Displays a sender authenticity trust badge in the message Reader.
 * Similar to Gmail's "this email may be a security risk" indicator.
 *
 * Rules:
 *   PASS    → Emerald "Sender Verified" (all checks passed, domain aligned)
 *   PARTIAL → Amber  "Partial Auth"     (some checks passed, alignment issues)
 *   FAIL    → Rose   "Auth Failed"      (DMARC explicitly failed — spoofing risk)
 *   NONE    → Shown only for external mail as slate "No Auth Info"
 *
 * Internal @thundermail.sougatatech.com mail always carries NONE and receives no badge
 * (the existing E2EE badge already communicates trust for those messages).
 */

import React, { useState, useEffect, useRef } from 'react';
import { ShieldCheck, ShieldAlert, ShieldX, Shield, X } from 'lucide-react';

// ─── Types ────────────────────────────────────────────────────────────────────

export type AuthStatus = 'PASS' | 'PARTIAL' | 'FAIL' | 'NONE';

interface AuthDetails {
  spf?:              string;
  dkim?:             string;
  dmarc?:            string;
  alignment?:        string;
  fromDomain?:       string;
  returnPathDomain?: string;
}

interface AuthBadgeProps {
  status:      AuthStatus;
  /** JSON string from the authDetails DB column (may be null/undefined) */
  detailsJson?: string | null;
  /** Pass true for internal domain messages to suppress the badge entirely */
  isInternal?: boolean;
}

interface DetailRowProps {
  label: string;
  value: string | undefined;
}

// ─── Config per status ────────────────────────────────────────────────────────

const STATUS_CONFIG = {
  PASS: {
    label:   'Sender Verified',
    tooltip: 'SPF, DKIM, and DMARC all passed with domain alignment. This message is very likely from a legitimate sender.',
    bg:      'bg-emerald-500/10',
    text:    'text-emerald-400',
    border:  'border-emerald-500/20',
    icon:    ShieldCheck,
    tip_bg:  'bg-emerald-950',
    tip_border: 'border-emerald-500/30',
  },
  PARTIAL: {
    label:   'Partial Auth',
    tooltip: 'Some authentication checks passed but DMARC is absent or domain alignment is incomplete. This could be a misconfigured-but-real sender.',
    bg:      'bg-amber-500/10',
    text:    'text-amber-400',
    border:  'border-amber-500/20',
    icon:    ShieldAlert,
    tip_bg:  'bg-amber-950',
    tip_border: 'border-amber-500/30',
  },
  FAIL: {
    label:   'Auth Failed',
    tooltip: 'DMARC verification failed. The From domain and sending infrastructure are misaligned — this could be a spoofed or forged sender.',
    bg:      'bg-rose-500/10',
    text:    'text-rose-400',
    border:  'border-rose-500/20',
    icon:    ShieldX,
    tip_bg:  'bg-rose-950',
    tip_border: 'border-rose-500/30',
  },
  NONE: {
    label:   'No Auth Info',
    tooltip: 'No SPF, DKIM, or DMARC information was available for this message. Treat with caution.',
    bg:      'bg-slate-500/10',
    text:    'text-slate-400',
    border:  'border-slate-500/20',
    icon:    Shield,
    tip_bg:  'bg-slate-900',
    tip_border: 'border-slate-500/30',
  },
} as const;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Extracted helper replacing nested ternary for detail status text color.
 */
function getAuthColor(value: string | undefined): string {
  switch (value) {
    case 'pass':
      return 'text-emerald-400';
    case 'fail':
      return 'text-rose-400';
    case 'softfail':
      return 'text-amber-400';
    default:
      return 'text-slate-400';
  }
}

// ─── Detail row sub-component ─────────────────────────────────────────────────

function DetailRow({ label, value }: Readonly<DetailRowProps>) {
  if (!value) return null;
  const colour = getAuthColor(value);

  return (
    <div className="flex items-center justify-between gap-4 text-[11px]">
      <span className="text-slate-400 font-medium">{label}</span>
      <span className={`font-mono uppercase font-semibold ${colour}`}>{value}</span>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export const AuthBadge: React.FC<Readonly<AuthBadgeProps>> = ({
  status,
  detailsJson,
  isInternal = false,
}) => {
  const [showTooltip, setShowTooltip] = useState(false);
  const dialogRef = useRef<HTMLDialogElement | null>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    if (showTooltip && !dialog.open) {
      dialog.showModal();
    } else if (!showTooltip && dialog.open) {
      dialog.close();
    }
  }, [showTooltip]);

  // Internal messages (thundermail.sougatatech.com ↔ thundermail.sougatatech.com) always have NONE
  // and the E2EE badge already communicates trust — suppress the auth badge
  if (isInternal && status === 'NONE') return null;

  const cfg = STATUS_CONFIG[status];
  const Icon = cfg.icon;

  let details: AuthDetails = {};
  if (detailsJson) {
    try {
      details = JSON.parse(detailsJson) as AuthDetails;
    } catch {
      // Non-fatal — just show the badge without detail breakdown
    }
  }

  const hasDetails =
    Boolean(details.spf || details.dkim || details.dmarc || details.alignment);

  return (
    <div className="relative inline-flex" id={`auth-badge-${status.toLowerCase()}`}>
      {/* ── Badge pill ─────────────────────────────────────────── */}
      <button
        type="button"
        aria-label={`Sender authentication: ${cfg.label}. Click for details.`}
        aria-expanded={showTooltip}
        onClick={() => setShowTooltip(prev => !prev)}
        className={`
          inline-flex items-center gap-1.5
          ${cfg.bg} ${cfg.text} border ${cfg.border}
          px-3 py-1 rounded-full text-xs font-medium
          cursor-pointer select-none
          transition-all duration-150
          hover:brightness-125 focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-1 focus-visible:ring-current
        `}
      >
        <Icon className="w-3.5 h-3.5" aria-hidden="true" />
        {cfg.label}
      </button>

      {/* ── Native Accessible Dialog Modal ──────────────────────── */}
      <dialog
        ref={dialogRef}
        aria-label="Authentication details"
        onClose={() => setShowTooltip(false)}
        className={`
          fixed m-auto z-50 backdrop:bg-black/60 backdrop:backdrop-blur-sm
          w-80 max-w-[90vw] rounded-xl border shadow-2xl
          ${cfg.tip_bg} ${cfg.tip_border}
          p-5 space-y-3.5 text-left
          animate-fade-in
        `}
      >
        {/* Close button & Header */}
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <Icon className={`w-4 h-4 ${cfg.text}`} aria-hidden="true" />
            <p className={`text-sm font-semibold ${cfg.text}`}>
              {cfg.label}
            </p>
          </div>
          <button
            type="button"
            aria-label="Close authentication details"
            onClick={() => setShowTooltip(false)}
            className="text-slate-500 hover:text-slate-300 transition-colors p-1 rounded-md hover:bg-white/10"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Explanation */}
        <p className="text-xs text-slate-300 leading-relaxed">
          {cfg.tooltip}
        </p>

        {/* Check results */}
        {hasDetails && (
          <div className={`border-t ${cfg.tip_border} pt-3 space-y-2`}>
            <DetailRow label="SPF"       value={details.spf} />
            <DetailRow label="DKIM"      value={details.dkim} />
            <DetailRow label="DMARC"     value={details.dmarc} />
            <DetailRow label="Alignment" value={details.alignment} />
            {details.fromDomain && (
              <div className="pt-2 border-t border-white/10 space-y-1.5">
                <DetailRow label="From domain"       value={details.fromDomain} />
                <DetailRow label="Return-Path domain" value={details.returnPathDomain} />
              </div>
            )}
          </div>
        )}

        {/* Warning for FAIL */}
        {status === 'FAIL' && (
          <div className="bg-rose-500/10 border border-rose-500/20 rounded-lg p-3">
            <p className="text-xs text-rose-300 leading-relaxed">
              ⚠️ <strong>Security Warning:</strong> The sender identity could not be verified. Do not click links or download attachments in this message.
            </p>
          </div>
        )}

        <div className="pt-2 flex justify-end">
          <button
            type="button"
            onClick={() => setShowTooltip(false)}
            className="px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-xs font-medium text-slate-200 transition-colors"
          >
            Done
          </button>
        </div>
      </dialog>
    </div>
  );
};
