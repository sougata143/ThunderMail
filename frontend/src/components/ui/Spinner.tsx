import React from 'react';

interface SpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  label?: string;
}

export const Spinner: React.FC<SpinnerProps> = ({ size = 'md', label }) => {
  const sizeMap = {
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-10 h-10',
  };

  return (
    <div className="flex flex-col items-center justify-center p-4 gap-3">
      <div className={`${sizeMap[size]} border-2 border-violet-500/30 border-t-violet-500 rounded-full animate-spin`} />
      {label && <p className="text-xs text-slate-400 tracking-wide font-medium">{label}</p>}
    </div>
  );
};
