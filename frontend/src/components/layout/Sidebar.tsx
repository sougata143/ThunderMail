import React from 'react';
import {
  Inbox,
  Send,
  FileText,
  Trash2,
  AlertOctagon,
  PenSquare,
  Shield,
  LogOut,
  HardDrive,
  Key,
} from 'lucide-react';
import { Button } from '../ui/Button.tsx';

interface SidebarProps {
  currentFolder: string;
  onSelectFolder: (folder: string) => void;
  onOpenComposer: () => void;
  onOpenSettings: () => void;
  onLogout: () => void;
  userEmail: string;
  storageUsedBytes?: number;
  storageQuotaBytes?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentFolder,
  onSelectFolder,
  onOpenComposer,
  onOpenSettings,
  onLogout,
  userEmail,
  storageUsedBytes = 1048576, // 1MB mock
  storageQuotaBytes = 1073741824, // 1GB
}) => {
  const folders = [
    { id: 'INBOX', label: 'Inbox', icon: Inbox },
    { id: 'SENT', label: 'Sent', icon: Send },
    { id: 'DRAFTS', label: 'Drafts', icon: FileText },
    { id: 'TRASH', label: 'Trash', icon: Trash2 },
    { id: 'SPAM', label: 'Spam', icon: AlertOctagon },
  ];

  const usagePercent = Math.min(
    100,
    Math.round((storageUsedBytes / storageQuotaBytes) * 100)
  );

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Number.parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  return (
    <aside className="w-64 h-screen glass-panel flex flex-col justify-between border-r border-white/10 p-4 select-none shrink-0">
      {/* Brand & Compose */}
      <div className="space-y-6">
        {/* Logo */}
        <div className="flex items-center gap-3 px-2">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-violet-700 to-violet-500 flex items-center justify-center shadow-glow-sm">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="font-bold text-base tracking-tight text-white flex items-center gap-1.5">
              <span>ThunderMail</span>
              <span className="text-[10px] bg-violet-500/20 text-violet-300 font-mono px-1.5 py-0.5 rounded border border-violet-500/30">
                E2EE
              </span>
            </h1>
            <p className="text-[11px] text-slate-400">Zero-Knowledge Webmail</p>
          </div>
        </div>

        {/* Compose Button */}
        <Button
          onClick={onOpenComposer}
          className="w-full justify-center py-2.5 shadow-glow"
          leftIcon={<PenSquare className="w-4 h-4" />}
        >
          New Secure Mail
        </Button>

        {/* Folder Navigation */}
        <nav className="space-y-1">
          {folders.map((item) => {
            const Icon = item.icon;
            const isActive = currentFolder.toUpperCase() === item.id;
            return (
              <button
                type="button"
                key={item.id}
                onClick={() => onSelectFolder(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-violet-600/20 text-violet-300 border border-violet-500/30 shadow-glow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-violet-400' : ''}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Storage & User Footer */}
      <div className="space-y-4 pt-4 border-t border-white/10">
        {/* Storage Bar */}
        <div className="bg-thunder-900/50 rounded-xl p-3 border border-white/5 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span className="flex items-center gap-1.5">
              <HardDrive className="w-3.5 h-3.5" />
              <span>Encrypted Storage</span>
            </span>
            <span className="font-mono text-[11px]">{usagePercent}%</span>
          </div>
          <div className="w-full bg-thunder-950 h-1.5 rounded-full overflow-hidden">
            <div
              className="bg-gradient-to-r from-violet-500 to-indigo-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${Math.max(4, usagePercent)}%` }}
            />
          </div>
          <div className="text-[10px] text-slate-500 font-mono text-right">
            {formatBytes(storageUsedBytes)} of {formatBytes(storageQuotaBytes)}
          </div>
        </div>

        {/* User profile & actions */}
        <div className="flex items-center justify-between px-1">
          <div className="flex flex-col min-w-0 pr-2">
            <span className="text-xs font-semibold text-slate-200 truncate">{userEmail}</span>
            <span className="text-[10px] text-emerald-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>Keys in RAM</span>
            </span>
          </div>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={onOpenSettings}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
              title="Security & Keys"
              aria-label="Security and Key Management"
            >
              <Key className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={onLogout}
              className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
              title="Lock Session & Logout"
              aria-label="Lock Session and Logout"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </aside>
  );
};
