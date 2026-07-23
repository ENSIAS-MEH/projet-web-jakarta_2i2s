package com.secbret.email;

import com.secbret.filter.CorrelationContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.concurrent.ManagedExecutorService;
import jakarta.annotation.Resource;
import jakarta.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.util.Properties;

/**
 * Fire-and-forget SMTP email dispatch (Part II §6 SMTP env vars).
 *
 * <p>Sends asynchronously via ManagedExecutorService so SMTP latency never blocks
 * the HTTP response. Failures are logged ERROR but do NOT roll back any caller
 * transaction (anti-enumeration requirement: password-reset must return 202
 * regardless of SMTP outcome).
 */
@ApplicationScoped
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    @Resource
    ManagedExecutorService executor;

    @Inject
    CorrelationContext correlationContext;

    /** Test constructor — inject executor directly (CDI-bypassed, correlationContext will be null). */
    public EmailService(ManagedExecutorService executor) {
        this.executor = executor;
    }

    public EmailService() {
    }

    /**
     * Sends a password-reset email asynchronously (fire-and-forget).
     * The caller's transaction has already committed before this is invoked.
     * Correlation ID is propagated into the worker thread MDC (Part II §9.5).
     *
     * @param toEmail   recipient address
     * @param resetUrl  full URL containing the plaintext token
     */
    public void sendPasswordResetAsync(String toEmail, String resetUrl) {
        // Capture correlation ID before async hop (§9.5 — @RequestScoped not available on worker thread).
        final String cid = correlationContext != null ? correlationContext.getAsString() : null;
        executor.execute(() -> {
            if (cid != null && !cid.isEmpty()) {
                MDC.put("correlationId", cid);
            }
            try {
                send(toEmail, "SecBret — password reset request",
                        "Click the link below to reset your password (expires in 1 hour):\n\n"
                                + resetUrl
                                + "\n\nIf you did not request this, you can ignore this email.");
                log.info("Password reset email sent to {}", maskEmail(toEmail));
            } catch (MessagingException e) {
                log.error("SMTP failure sending password-reset email to {} — token remains valid: {}",
                        maskEmail(toEmail), e.getMessage());
            } finally {
                MDC.remove("correlationId");
            }
        });
    }

    private void send(String to, String subject, String body) throws MessagingException {
        String host = System.getenv("SMTP_HOST");
        if (host == null || host.isBlank()) {
            log.warn("SMTP_HOST not configured — skipping email send (to={})", maskEmail(to));
            return;
        }

        String port   = nvl(System.getenv("SMTP_PORT"), "587");
        boolean tls   = !"false".equalsIgnoreCase(System.getenv("SMTP_TLS"));
        String user   = nvl(System.getenv("SMTP_USERNAME"), "");
        String pass   = nvl(System.getenv("SMTP_PASSWORD"), "");
        String from   = nvl(System.getenv("SMTP_FROM"), "noreply@secbret.local");

        Properties props = new Properties();
        props.put("mail.smtp.host", host);
        props.put("mail.smtp.port", port);
        if (tls) {
            props.put("mail.smtp.starttls.enable", "true");
        }
        props.put("mail.smtp.auth", (!user.isBlank()) ? "true" : "false");

        Session session;
        if (!user.isBlank()) {
            final String u = user;
            final String p = pass;
            session = Session.getInstance(props, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(u, p);
                }
            });
        } else {
            session = Session.getInstance(props);
        }

        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress(from));
        msg.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
        msg.setSubject(subject);
        msg.setText(body);
        Transport.send(msg);
    }

    private static String nvl(String v, String def) {
        return (v == null || v.isBlank()) ? def : v;
    }

    /** Masks email for logging — e.g. "u***@example.com". */
    private static String maskEmail(String email) {
        if (email == null) return "(null)";
        int at = email.indexOf('@');
        if (at <= 1) return "***";
        return email.charAt(0) + "***" + email.substring(at);
    }
}
