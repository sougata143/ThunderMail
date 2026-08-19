import React from 'react';
import { Search, Shield, RefreshCw } from 'lucide-react';

interface HeaderProps {
  searchQuery: string;
  onSearchChange: (q: string) => void;
  onRefresh: () => void;
  isLoading?: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  searchQuery,
  onSearchChange,
  onRefresh,
  isLoading = false,
}) => {
  return (
    <header className="h-16 glass-panel border-b border-white/10 px-6 flex items-center justify-between gap-4 shrink-0">
      {/* Search Input with client-side zero-knowledge disclaimer */}
      <div className="flex-1 max-w-xl relative">
        <div className="relative">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search sender, recipient, metadata..."
            className="w-full glass-input rounded-xl pl-10 pr-24 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none"
          />
          <span className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px] text-slate-500 font-mono bg-white/5 px-2 py-0.5 rounded">
            E2EE Client Search
          </span>
        </div>
      </div>

      {/* Action icons & status */}
      <div className="flex items-center gap-3">
        <button
          onClick={onRefresh}
          className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
          title="Refresh Mailbox"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-violet-400' : ''}`} />
        </button>

        <div className="hidden sm:flex items-center gap-2 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-3 py-1 rounded-full text-xs font-medium">
          <Shield className="w-3.5 h-3.5" />
          <span>Zero-Knowledge Protected</span>
        </div>
      </div>
    </header>
  );
};
