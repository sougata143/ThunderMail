import nodemailer from 'nodemailer';
import { env } from '../config/env.js';

interface ExternalMailParams {
  from: string;
  to: string;
  subject: string;
  body: string;
}

/**
 * Creates a Nodemailer SMTP transport for external relay.
 * Supports: SendGrid, Brevo, Postmark, OCI Email Delivery, Mailgun (port 587 STARTTLS).
 */
const createTransport = () => {
  if (!env.SMTP_HOST || !env.SMTP_USER || !env.SMTP_PASS) {
    console.warn('⚠️  SMTP not configured — external email relay disabled.');
    return null;
  }

  return nodemailer.createTransport({
    host: env.SMTP_HOST,
    port: env.SMTP_PORT,
    secure: false, // STARTTLS on port 587
    auth: {
      user: env.SMTP_USER,
      pass: env.SMTP_PASS,
    },
    tls: {
      ciphers: 'SSLv3',
      rejectUnauthorized: true,
    },
  });
};

export const smtpRelayService = {
  /**
   * Relay an external email via SMTP.
   * Called when recipient is NOT on this ThunderMail server.
   * Sends the decrypted plaintext — client chose to send external, accepting no E2EE.
   */
  async sendExternal(params: ExternalMailParams): Promise<void> {
    const transport = createTransport();

    if (!transport) {
      console.error('SMTP relay not configured. Cannot send external email.');
      throw new Error('SMTP relay not configured. Contact your administrator.');
    }

    await transport.sendMail({
      from: `ThunderMail <${env.SMTP_FROM}>`,
      replyTo: params.from,
      to: params.to,
      subject: params.subject,
      text: params.body,
      html: `<div style="font-family:sans-serif;max-width:600px;">${params.body.replaceAll('\n', '<br>')}</div>`,
      headers: {
        'X-Mailer': 'ThunderMail E2EE',
        'X-ThunderMail-External': 'true',
      },
    });

    console.log(`📧 External email relayed: ${params.from} → ${params.to}`);
  },

  /**
   * Send a notification to an external user that they have a secure message.
   * Does NOT include content — just a link to the sender's ThunderMail.
   */
  async sendE2eeNotification(params: {
    from: string;
    to: string;
    domain: string;
  }): Promise<void> {
    const transport = createTransport();
    if (!transport) return;

    await transport.sendMail({
      from: `ThunderMail <${env.SMTP_FROM}>`,
      to: params.to,
      subject: `You have a new secure message from ${params.from}`,
      text: [
        `${params.from} sent you a secure, end-to-end encrypted message via ThunderMail.`,
        '',
        `To read it, visit: https://${params.domain}`,
        '',
        'ThunderMail — Zero-Knowledge Encrypted Email',
      ].join('\n'),
    });
  },
};
