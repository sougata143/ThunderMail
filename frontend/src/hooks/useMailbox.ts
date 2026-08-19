import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { mailApi, type FolderResponse } from '../api/mail.api.ts';
import { keysApi } from '../api/keys.api.ts';
import { useCrypto } from './useCrypto.ts';

export function useMailbox(folderName = 'INBOX', page = 1) {
  const queryClient = useQueryClient();
  const { encryptMessage, decryptMessage, privateKey } = useCrypto();

  // Query folder messages
  const folderQuery = useQuery<FolderResponse>({
    queryKey: ['mailbox', folderName, page],
    queryFn: () => mailApi.getFolder(folderName, page),
    refetchInterval: 15000, // Background poll every 15s
    enabled: !!privateKey,
  });

  // Query single full message
  const useMessageDetail = (messageId: string | null) =>
    useQuery({
      queryKey: ['message', messageId],
      queryFn: async () => {
        if (!messageId) return null;
        const msg = await mailApi.getMail(messageId);

        // Decrypt message content client-side
        if (msg.isE2ee) {
          // Choose appropriate session key: if user is sender in SENT folder, use senderSessionKey
          const isSentCopy = folderName === 'SENT' || msg.folder === 'SENT';
          const sessionKeyToUse = isSentCopy && msg.senderSessionKey
            ? msg.senderSessionKey
            : msg.encryptedSessionKey;

          const decrypted = await decryptMessage({
            encryptedSessionKey: sessionKeyToUse,
            encryptedSubject: msg.encryptedSubject,
            encryptedBody: msg.encryptedBody,
            subjectIv: msg.subjectIv,
            bodyIv: msg.bodyIv,
            encryptedAttachmentsMetadata: msg.encryptedAttachmentsMetadata,
          });

          return {
            ...msg,
            decryptedSubject: decrypted.subject,
            decryptedBody: decrypted.body,
          };
        }

        return {
          ...msg,
          decryptedSubject: msg.encryptedSubject,
          decryptedBody: msg.encryptedBody,
        };
      },
      enabled: !!messageId && !!privateKey,
    });

  // Mutation: Send Email
  const sendMutation = useMutation({
    mutationFn: async (params: {
      recipientEmail: string;
      subject: string;
      body: string;
    }) => {
      // 1. Check if recipient exists for E2EE or fallback to TLS relay
      try {
        const keyInfo = await keysApi.getPublicKey(params.recipientEmail);
        // Recipient found -> E2EE
        const encryptedPayload = await encryptMessage({
          recipientEmail: params.recipientEmail,
          subject: params.subject,
          body: params.body,
          recipientPublicKeyPem: keyInfo.publicKey,
        });
        return await mailApi.sendMail(encryptedPayload);
      } catch (err: unknown) {
        // Recipient not found on server -> Relay with client-assisted plaintext payload
        const status = (err as { response?: { status?: number } })?.response?.status;
        if (status === 404) {
          return await mailApi.sendMail({
            recipientEmail: params.recipientEmail,
            encryptedSessionKey: 'RELAY_NO_KEY',
            senderSessionKey: 'RELAY_NO_KEY',
            encryptedSubject: params.subject,
            encryptedBody: params.body,
            subjectIv: 'RELAY_IV',
            bodyIv: 'RELAY_IV',
            isE2ee: false,
            plaintextSubject: params.subject,
            plaintextBody: params.body,
          });
        }
        throw err;
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mailbox'] });
    },
  });

  // Mutation: Patch Status (Mark Read / Move Folder)
  const patchStatusMutation = useMutation({
    mutationFn: (params: { id: string; isRead?: boolean; folder?: string }) =>
      mailApi.patchStatus(params.id, { isRead: params.isRead, folder: params.folder }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mailbox'] });
    },
  });

  // Mutation: Delete Email
  const deleteMutation = useMutation({
    mutationFn: (id: string) => mailApi.deleteMail(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mailbox'] });
    },
  });

  return {
    folderData: folderQuery.data,
    isLoading: folderQuery.isLoading,
    isError: folderQuery.isError,
    refetch: folderQuery.refetch,
    useMessageDetail,
    sendEmail: sendMutation.mutateAsync,
    isSending: sendMutation.isPending,
    patchStatus: patchStatusMutation.mutateAsync,
    deleteEmail: deleteMutation.mutateAsync,
  };
}
