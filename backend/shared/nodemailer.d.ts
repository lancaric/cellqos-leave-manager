declare module "nodemailer" {
  namespace nodemailer {
    interface TransportOptions {
      host?: string;
      port?: number;
      secure?: boolean;
      ignoreTLS?: boolean;
      requireTLS?: boolean;
      auth?: {
        user: string;
        pass: string;
      };
      tls?: {
        rejectUnauthorized?: boolean;
      };
    }

    interface SendMailOptions {
      from?: string;
      to?: string;
      subject?: string;
      text?: string;
      attachments?: Array<{
        filename?: string;
        content?: string | Buffer;
        contentType?: string;
      }>;
    }

    interface Transporter {
      sendMail(options: SendMailOptions): Promise<unknown>;
    }
  }

  function createTransport(options: nodemailer.TransportOptions): nodemailer.Transporter;

  const nodemailer: {
    createTransport: typeof createTransport;
  };

  export = nodemailer;
}
