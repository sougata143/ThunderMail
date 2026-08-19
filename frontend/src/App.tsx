import React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { CryptoProvider } from './hooks/useCrypto.ts';
import { AuthProvider, useAuth } from './hooks/useAuth.ts';
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

// AppContent reads from the shared AuthContext — re-renders when login/logout fires
const AppContent: React.FC = () => {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? <MailboxPage /> : <AuthPage />;
};

export const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      {/* CryptoProvider must wrap AuthProvider so useCrypto() is available inside AuthProvider */}
      <CryptoProvider>
        <AuthProvider>
          <AppContent />
        </AuthProvider>
      </CryptoProvider>
    </QueryClientProvider>
  );
};

export default App;
