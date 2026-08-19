import React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { CryptoProvider } from './hooks/useCrypto.ts';
import { useAuth } from './hooks/useAuth.ts';
import { AuthPage } from './pages/AuthPage.tsx';
import { MailboxPage } from './pages/MailboxPage.tsx';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

const AppContent: React.FC = () => {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? <MailboxPage /> : <AuthPage />;
};

export const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <CryptoProvider>
        <AppContent />
      </CryptoProvider>
    </QueryClientProvider>
  );
};

export default App;
