import React, { useState } from 'react';
import { Sidebar } from '../components/layout/Sidebar.tsx';
import { Header } from '../components/layout/Header.tsx';
import { MailList } from '../components/layout/MailList.tsx';
import { Reader } from '../components/layout/Reader.tsx';
import { Composer } from '../components/layout/Composer.tsx';
import { KeyExportModal } from '../components/crypto/KeyExportModal.tsx';
import { useAuth } from '../hooks/useAuth.ts';
import { useMailbox } from '../hooks/useMailbox.ts';
import { APP_DOMAIN } from '../config/app.ts';

export const MailboxPage: React.FC = () => {
  const { user, logout } = useAuth();
  const [currentFolder, setCurrentFolder] = useState('INBOX');
  const [selectedMessageId, setSelectedMessageId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  // Modals state
  const [isComposerOpen, setIsComposerOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [composerInitial, setComposerInitial] = useState({ to: '', subject: '' });

  const { folderData, isLoading, refetch, deleteEmail } = useMailbox(currentFolder);

  // Filter messages by search query
  const filteredMessages = (folderData?.messages || []).filter((msg) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      msg.senderEmail.toLowerCase().includes(q) ||
      msg.recipientEmail.toLowerCase().includes(q)
    );
  });

  const handleReply = (to: string, originalSubject: string) => {
    const replySubject = originalSubject.startsWith('Re:')
      ? originalSubject
      : `Re: ${originalSubject}`;
    setComposerInitial({ to, subject: replySubject });
    setIsComposerOpen(true);
  };

  const handleDelete = async (id: string) => {
    await deleteEmail(id);
    if (selectedMessageId === id) {
      setSelectedMessageId(null);
    }
  };

  return (
    <div className="flex h-screen w-screen bg-thunder-950 text-slate-100 overflow-hidden select-none">
      {/* 1. Left Sidebar */}
      <Sidebar
        currentFolder={currentFolder}
        onSelectFolder={(folder) => {
          setCurrentFolder(folder);
          setSelectedMessageId(null);
        }}
        onOpenComposer={() => {
          setComposerInitial({ to: '', subject: '' });
          setIsComposerOpen(true);
        }}
        onOpenSettings={() => setIsSettingsOpen(true)}
        onLogout={logout}
        userEmail={user?.email || `user@${APP_DOMAIN}`}
      />

      {/* Main Mailbox Content Area */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        {/* Top Header */}
        <Header
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          onRefresh={refetch}
          isLoading={isLoading}
        />

        {/* Two-pane Mail View: MailList + Reader */}
        <div className="flex-1 flex h-[calc(100vh-64px)] overflow-hidden">
          {/* 2. Message List Column */}
          <MailList
            messages={filteredMessages}
            selectedId={selectedMessageId}
            onSelectMessage={setSelectedMessageId}
            isLoading={isLoading}
            folderName={currentFolder}
          />

          {/* 3. Reading Pane */}
          <Reader
            messageId={selectedMessageId}
            folderName={currentFolder}
            onReply={handleReply}
            onDelete={handleDelete}
          />
        </div>
      </div>

      {/* Composer Drawer */}
      <Composer
        isOpen={isComposerOpen}
        onClose={() => setIsComposerOpen(false)}
        initialTo={composerInitial.to}
        initialSubject={composerInitial.subject}
      />

      {/* Security & Key Export Modal */}
      <KeyExportModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        userEmail={user?.email || ''}
      />
    </div>
  );
};
