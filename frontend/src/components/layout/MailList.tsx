import React, { useState, useEffect } from 'react';
import { Lock, Mail, MailOpen } from 'lucide-react';
import type { EnvelopeSummary } from '../../api/mail.api.ts';
import { useCrypto } from '../../hooks/useCrypto.ts';

interface MailListProps {
  messages: EnvelopeSummary[];
  selectedId: string | null;
  onSelectMessage: (id: string) => void;
  isLoading: boolean;
  folderName: string;
}

export const MailList: React.FC<MailListProps> = ({
  messages,
  selectedId,
  onSelectMessage,
  isLoading,
  folderName,
}) => {
  const { decryptMessage } = useCrypto();
  const [decryptedSubjects, setDecryptedSubjects] = useState<Record<string, string>>({});

  // Decrypt subjects client-side as envelopes arrive
  useEffect(() => {
    let isCancelled = false;

    async function decryptAllSubjects() {
      const subjectMap: Record<string, string> = {};

      for (const msg of messages) {
        if (!msg.isE2ee) {
          subjectMap[msg.id] = msg.encryptedSubject;
          continue;
        }

        try {
          // If in SENT folder, use senderSessionKey if available
          const isSentCopy = folderName === 'SENT' || msg.folder === 'SENT';
          const sessionKeyToUse = isSentCopy && msg.senderSessionKey
            ? msg.senderSessionKey
            : msg.encryptedSessionKey;

          const res = await decryptMessage({
            encryptedSessionKey: sessionKeyToUse,
            encryptedSubject: msg.encryptedSubject,
            encryptedBody: '', // not needed for subject decryption preview
            subjectIv: msg.subjectIv,
            bodyIv: msg.subjectIv, // dummy for preview
          });
          subjectMap[msg.id] = res.subject;
        } catch {
          subjectMap[msg.id] = '[Encrypted Subject]';
        }
      }

      if (!isCancelled) {
        setDecryptedSubjects(subjectMap);
      }
    }

    if (messages.length > 0) {
      decryptAllSubjects();
    }

    return () => {
      isCancelled = true;
    };
  }, [messages, decryptMessage, folderName]);

  const formatDate = (isoString: string) => {
    const date = new Date(isoString);
    const now = new Date();
    const isToday = date.toDateString() === now.toDateString();

    if (isToday) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
  };

  if (isLoading) {
    return (
      <div className="w-80 h-full border-r border-white/10 p-4 space-y-3 shrink-0">
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="h-20 rounded-xl bg-white/5 animate-pulse" />
        ))}
      </div>
    );
  }

  if (messages.length === 0) {
    return (
      <div className="w-80 h-full border-r border-white/10 flex flex-col items-center justify-center p-6 text-center text-slate-500 shrink-0">
        <Mail className="w-10 h-10 mb-2 opacity-30" />
        <p className="text-sm font-medium">No messages in {folderName}</p>
        <p className="text-xs text-slate-600 mt-1">Your zero-knowledge inbox is clear</p>
      </div>
    );
  }

  return (
    <div className="w-80 h-full border-r border-white/10 flex flex-col shrink-0 overflow-y-auto divide-y divide-white/5">
      {messages.map((msg) => {
        const isSelected = msg.id === selectedId;
        const subject = decryptedSubjects[msg.id] || 'Decrypting...';
        const displayParty = folderName === 'SENT' ? `To: ${msg.recipientEmail}` : msg.senderEmail;

        return (
          <button
            type="button"
            key={msg.id}
            onClick={() => onSelectMessage(msg.id)}
            className={`w-full text-left p-4 transition-all duration-150 relative group ${
              isSelected
                ? 'bg-violet-600/15 border-l-2 border-violet-500'
                : 'hover:bg-white/5'
            }`}
          >
            {/* Top row: sender + time */}
            <div className="flex items-center justify-between gap-2 mb-1.5">
              <span
                className={`text-xs font-semibold truncate ${
                  msg.isRead ? 'text-slate-300' : 'text-white'
                }`}
              >
                {displayParty}
              </span>
              <span className="text-[11px] text-slate-500 font-mono shrink-0">
                {formatDate(msg.createdAt)}
              </span>
            </div>

            {/* Subject */}
            <p
              className={`text-sm truncate mb-2 ${
                msg.isRead ? 'text-slate-400 font-normal' : 'text-slate-100 font-medium'
              }`}
            >
              {subject}
            </p>

            {/* Badges */}
            <div className="flex items-center gap-2">
              {msg.isE2ee ? (
                <span className="inline-flex items-center gap-1 text-[10px] bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5 rounded font-mono border border-emerald-500/20">
                  <Lock className="w-2.5 h-2.5" />
                  E2EE
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-[10px] bg-amber-500/10 text-amber-400 px-1.5 py-0.5 rounded font-mono border border-amber-500/20">
                  TLS Relay
                </span>
              )}

              {!msg.isRead && (
                <span className="w-2 h-2 rounded-full bg-violet-500 shrink-0 shadow-glow-sm" />
              )}
            </div>

            {/* Read status icon hover preview */}
            <div className="absolute right-3 bottom-3 opacity-0 group-hover:opacity-100 transition-opacity">
              {msg.isRead ? (
                <MailOpen className="w-3.5 h-3.5 text-slate-500" />
              ) : (
                <Mail className="w-3.5 h-3.5 text-violet-400" />
              )}
            </div>
          </button>
        );
      })}
    </div>
  );
};
