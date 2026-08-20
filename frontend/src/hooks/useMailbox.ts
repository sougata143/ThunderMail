import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { mailApi, type FolderResponse, type FullMessageRecord } from '../api/mail.api.ts';
import { keysApi } from '../api/keys.api.ts';
import { useCrypto } from './useCrypto.ts';

// ─── Helpers for Cognitive Complexity Reduction ───────────────────────────────

/**
 * Selects the appropriate session key and KEM ciphertexts based on whether
 * the message is being viewed from the user's SENT folder copy.
 */
function resolveEnvelopeCiphertexts(msg: FullMessageRecord, activeFolder: string) {
  const isSentCopy = activeFolder === 'SENT' || msg.folder === 'SENT';

  const sessionKey = (isSentCopy && msg.senderSessionKey)
    ? msg.senderSessionKey
    : msg.encryptedSessionKey;

  const classicCiphertext = (isSentCopy && msg.senderClassicCt)
    ? msg.senderClassicCt
    : msg.classicCiphertext;

  const pqcCiphertext = (isSentCopy && msg.senderPqcCt)
    ? msg.senderPqcCt
    : msg.pqcCiphertext;

  return { sessionKey, classicCiphertext, pqcCiphertext };
}

/**
 * Fetches the sender's ML-DSA-65 public key when a signature is present.
 */
async function fetchSenderDsaKey(senderEmail: string, hasSignature: boolean): Promise<string | null> {
  if (!hasSignature) return null;
  try {
    const senderKeyInfo = await keysApi.getPublicKey(senderEmail);
    return senderKeyInfo.dsaPublicKey ?? null;
  } catch {
    return null;
  }
}

// ─── Main Hook ────────────────────────────────────────────────────────────────

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

        // Non-E2EE messages return plaintext directly
        if (!msg.isE2ee) {
          return {
            ...msg,
            decryptedSubject: msg.encryptedSubject,
            decryptedBody: msg.encryptedBody,
            signatureStatus: 'UNSIGNED' as const,
          };
        }

        // Decrypt E2EE message content client-side
        const { sessionKey, classicCiphertext, pqcCiphertext } = resolveEnvelopeCiphertexts(msg, folderName);
        const senderDsaPublicKey = await fetchSenderDsaKey(msg.senderEmail, Boolean(msg.senderSignature));

        const decrypted = await decryptMessage({
          encryptedSessionKey: sessionKey,
          encryptedSubject: msg.encryptedSubject,
          encryptedBody: msg.encryptedBody,
          subjectIv: msg.subjectIv,
          bodyIv: msg.bodyIv,
          encryptedAttachmentsMetadata: msg.encryptedAttachmentsMetadata,
          isPqc: msg.isPqc,
          classicCiphertext,
          pqcCiphertext,
          senderSignature: msg.senderSignature,
          senderDsaPublicKey,
        });

        return {
          ...msg,
          decryptedSubject: decrypted.subject,
          decryptedBody: decrypted.body,
          signatureStatus: decrypted.signatureStatus,
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
        // Recipient found -> Hybrid E2EE
        const encryptedPayload = await encryptMessage({
          recipientEmail: params.recipientEmail,
          subject: params.subject,
          body: params.body,
          recipientPublicKeyPem: keyInfo.publicKey,
          recipientPqcPublicKey: keyInfo.pqcPublicKey,
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
            isPqc: false,
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
