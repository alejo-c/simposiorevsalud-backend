use lettre::{
    message::{header::ContentType, Mailbox, Message},
    transport::smtp::{
        authentication::{Credentials, Mechanism},
        PoolConfig,
    },
    SmtpTransport, Transport,
};
use std::{error::Error, time::Duration};

pub struct EmailConfig {
    pub smtp_server: String,
    pub smtp_port: u16,
    pub sender_email: String,
    pub password: String,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            smtp_server: "smtp.office365.com".to_string(),
            smtp_port: 587,
            sender_email: "simposiorevsalud@udenar.edu.co".to_string(),
            password: "testpasswd".to_string(),
        }
    }
}

pub struct EmailService {
    config: EmailConfig,
    mailer: SmtpTransport,
}

impl EmailService {
    pub fn new(config: EmailConfig) -> Result<Self, Box<dyn Error>> {
        let creds = Credentials::new(config.sender_email.clone(), config.password.clone());

        let mailer = SmtpTransport::relay(&config.smtp_server)?
            .port(config.smtp_port)
            .credentials(creds)
            .authentication(vec![Mechanism::Login, Mechanism::Plain])
            .pool_config(PoolConfig::new().max_size(10))
            .timeout(Some(Duration::from_secs(60)))
            .build();

        Ok(Self { config, mailer })
    }

    pub fn new_with_default_config() -> Result<Self, Box<dyn Error>> {
        Self::new(EmailConfig::default())
    }

    pub fn send_email(
        &self,
        to: &str,
        subject: &str,
        body: &str,
        is_html: bool,
    ) -> Result<(), Box<dyn Error>> {
        let from: Mailbox = self.config.sender_email.parse()?;
        let to: Mailbox = to.parse()?;

        let message_builder = Message::builder().from(from).to(to).subject(subject);

        let message = if is_html {
            message_builder
                .header(ContentType::TEXT_HTML)
                .body(body.to_string())?
        } else {
            message_builder
                .header(ContentType::TEXT_PLAIN)
                .body(body.to_string())?
        };

        match self.mailer.send(&message) {
            Ok(_) => Ok(()),
            Err(e) => Err(Box::new(e)),
        }
    }

    pub fn send_html_email(
        &self,
        to: &str,
        subject: &str,
        html_body: &str,
    ) -> Result<(), Box<dyn Error>> {
        self.send_email(to, subject, html_body, true)
    }

    pub fn send_text_email(
        &self,
        to: &str,
        subject: &str,
        text_body: &str,
    ) -> Result<(), Box<dyn Error>> {
        self.send_email(to, subject, text_body, false)
    }

    pub fn send_multipart_email(
        &self,
        to: &str,
        subject: &str,
        text_body: &str,
        html_body: &str,
    ) -> Result<(), Box<dyn Error>> {
        use lettre::message::{MultiPart, SinglePart};

        let from: Mailbox = self.config.sender_email.parse()?;
        let to: Mailbox = to.parse()?;

        let message = Message::builder()
            .from(from)
            .to(to)
            .subject(subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text_body.to_string()),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html_body.to_string()),
                    ),
            )?;

        match self.mailer.send(&message) {
            Ok(_) => Ok(()),
            Err(e) => Err(Box::new(e)),
        }
    }

    pub fn send_email_with_cc_bcc(
        &self,
        to: &str,
        cc: Option<&str>,
        bcc: Option<&str>,
        subject: &str,
        body: &str,
        is_html: bool,
    ) -> Result<(), Box<dyn Error>> {
        let from: Mailbox = self.config.sender_email.parse()?;
        let to: Mailbox = to.parse()?;

        let mut message_builder = Message::builder().from(from).to(to).subject(subject);

        if let Some(cc_addr) = cc {
            let cc_mailbox: Mailbox = cc_addr.parse()?;
            message_builder = message_builder.cc(cc_mailbox);
        }

        if let Some(bcc_addr) = bcc {
            let bcc_mailbox: Mailbox = bcc_addr.parse()?;
            message_builder = message_builder.bcc(bcc_mailbox);
        }

        let message = if is_html {
            message_builder
                .header(ContentType::TEXT_HTML)
                .body(body.to_string())?
        } else {
            message_builder
                .header(ContentType::TEXT_PLAIN)
                .body(body.to_string())?
        };

        match self.mailer.send(&message) {
            Ok(_) => Ok(()),
            Err(e) => Err(Box::new(e)),
        }
    }
}

// Convenience functions for quick email sending
pub fn send_quick_email(
    to: &str,
    subject: &str,
    body: &str,
    is_html: bool,
) -> Result<(), Box<dyn Error>> {
    let email_service = EmailService::new_with_default_config()?;
    email_service.send_email(to, subject, body, is_html)
}

pub fn send_quick_html_email(
    to: &str,
    subject: &str,
    html_body: &str,
) -> Result<(), Box<dyn Error>> {
    send_quick_email(to, subject, html_body, true)
}

pub fn send_quick_text_email(
    to: &str,
    subject: &str,
    text_body: &str,
) -> Result<(), Box<dyn Error>> {
    send_quick_email(to, subject, text_body, false)
}

pub fn send_register_mail(to: &str) -> Result<(), Box<dyn Error>> {
    send_quick_html_email(to, "Usuario registrado", "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_config_default() {
        let config = EmailConfig::default();
        assert_eq!(config.smtp_server, "smtp.office365.com");
        assert_eq!(config.smtp_port, 587);
        assert_eq!(config.sender_email, "simposiorevsalud@udenar.edu.co");
    }

    #[test]
    fn test_email_service_creation() {
        let config = EmailConfig::default();
        let result = EmailService::new(config);
        assert!(result.is_ok());
    }
}
