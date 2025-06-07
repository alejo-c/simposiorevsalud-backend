use crate::email::{EmailService, EmailConfig, send_quick_text_email};

// Using the default configuration
let email_service = EmailService::new_with_default_config()?;
email_service.send_text_email(
    "recipient@example.com",
    "Test Subject",
    "Hello, this is a test email!"
)?;

// Using custom configuration
let custom_config = EmailConfig {
    smtp_server: "smtp.office365.com".to_string(),
    smtp_port: 587,
    sender_email: "simposiorevsalud@udenar.edu.co".to_string(),
    password: "your_actual_password".to_string(),
};
let email_service = EmailService::new(custom_config)?;

// Send HTML email
email_service.send_html_email(
    "recipient@example.com",
    "HTML Email",
    "<h1>Hello</h1><p>This is an HTML email!</p>"
)?;

// Quick send function
send_quick_text_email(
    "recipient@example.com",
    "Quick Email",
    "This is a quick email!"
)?;
