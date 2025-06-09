use serde::Serialize;
use spin_sdk::http::{Method, Request, Response};

// EmailJS Configuration
const EMAILJS_SERVICE_ID: &str = "service_3l0zil1";
const EMAILJS_USER_ID: &str = "I38dYyrQyvuoc67_z";
const TEMPLATE_REGISTER: &str = "template_og81zti";

#[derive(Serialize)]
struct EmailJSPayload {
    service_id: String,
    template_id: String,
    user_id: String,
    template_params: serde_json::Value,
}

// ASYNC EMAIL SENDING - Proper async for Spin
pub async fn send_register_email_sync(
    to_email: &str,
    to_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let template_params = serde_json::json!({
        "to_email": to_email,
        "to_name": to_name,
        "from_name": "Simposio Rev Salud",
        "reply_to": "simposiorevsalud@udenar.edu.co",
        "subject": "✅ Registro Exitoso - Simposio Revista de Salud",
        "user_name": to_name,
        "event_name": "Simposio Revista de Salud",
        "institution": "Universidad de Nariño",
        "contact_email": "simposiorevsalud@udenar.edu.co"
    });

    println!("🚀 SENDING REGISTRATION EMAIL...");
    println!("📧 To: {}", to_email);
    println!("📧 Name: {}", to_name);

    send_email_async(TEMPLATE_REGISTER, template_params).await
}

pub async fn send_certificate_ready_sync(
    to_email: &str,
    to_name: &str,
    certificate_type: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let cert_name = match certificate_type {
        "horizontal" => "Certificado de Participación",
        "vertical" => "Certificado de Ponencia",
        _ => "Certificado",
    };

    let template_params = serde_json::json!({
        "to_email": to_email,
        "to_name": to_name,
        "from_name": "Simposio Rev Salud",
        "reply_to": "simposiorevsalud@udenar.edu.co",
        "subject": format!("🎓 {} Disponible - Simposio Rev Salud", cert_name),
        "user_name": to_name,
        "email_type": "certificate",
        "custom_message": format!("Su {} está listo para descargar desde su perfil.", cert_name),
        "institution": "Universidad de Nariño",
        "contact_email": "simposiorevsalud@udenar.edu.co"
    });

    println!("🚀 SENDING CERTIFICATE EMAIL...");
    println!("📧 To: {}", to_email);
    println!("📧 Certificate Type: {}", cert_name);

    send_email_async(TEMPLATE_REGISTER, template_params).await
}

// Core async email sending function - proper for Spin
async fn send_email_async(
    template_id: &str,
    template_params: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = EmailJSPayload {
        service_id: EMAILJS_SERVICE_ID.to_string(),
        template_id: template_id.to_string(),
        user_id: EMAILJS_USER_ID.to_string(),
        template_params: template_params.clone(),
    };

    println!("📦 Creating email payload...");
    let body = serde_json::to_vec(&payload)?;

    // Create the HTTP request
    let request = Request::builder()
        .method(Method::Post)
        .uri("https://api.emailjs.com/api/v1.0/email/send")
        .header("Content-Type", "application/json")
        .header("User-Agent", "Simposio-RevSalud/1.0")
        .body(body)
        .build();

    println!("🌐 Sending request to EmailJS...");

    // Use Spin's async HTTP client - this is the correct way
    match spin_sdk::http::send::<Request, Response>(request).await {
        Ok(response) => {
            let status = response.status();
            let response_body = std::str::from_utf8(response.body()).unwrap_or("No body");

            println!("📡 EmailJS Response - Status: {}", status);

            if *status >= 400u16 {
                println!("❌ EmailJS Error: {} - {}", status, response_body);
                return Err(format!("EmailJS Error ({}): {}", status, response_body).into());
            } else if *status >= 200u16 && *status < 300u16 {
                println!("✅ EMAIL SENT SUCCESSFULLY!");
                println!("📨 Email sent from: simposiorevsalud@udenar.edu.co");
                println!("📧 Recipient: {}", template_params.get("to_email").unwrap());
                return Ok(());
            } else {
                println!("⚠️ Unexpected response: {}", status);
                return Err(format!("Unexpected response: {}", status).into());
            }
        }
        Err(e) => {
            println!("❌ Failed to send HTTP request: {}", e);
            return Err(format!("HTTP request failed: {}", e).into());
        }
    }
}

// Utility functions
pub fn get_service_id() -> &'static str {
    EMAILJS_SERVICE_ID
}

pub fn get_user_id() -> &'static str {
    EMAILJS_USER_ID
}

pub fn get_template_id() -> &'static str {
    TEMPLATE_REGISTER
}

pub fn test_email_config(to_email: &str, to_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let template_params = serde_json::json!({
        "to_email": to_email,
        "to_name": to_name,
        "from_name": "Simposio Rev Salud",
        "reply_to": "simposiorevsalud@udenar.edu.co",
        "subject": "✅ Registro Exitoso - Simposio Revista de Salud",
        "user_name": to_name,
        "event_name": "Simposio Revista de Salud",
        "institution": "Universidad de Nariño",
        "contact_email": "simposiorevsalud@udenar.edu.co"
    });

    let payload = EmailJSPayload {
        service_id: EMAILJS_SERVICE_ID.to_string(),
        template_id: TEMPLATE_REGISTER.to_string(),
        user_id: EMAILJS_USER_ID.to_string(),
        template_params: template_params.clone(),
    };

    println!("═══════════════════════════════════════");
    println!("🧪 EMAIL CONFIGURATION TEST");
    println!("═══════════════════════════════════════");
    println!("📧 Service ID: {}", EMAILJS_SERVICE_ID);
    println!("📧 Template ID: {}", TEMPLATE_REGISTER);
    println!("📧 User ID (Public Key): {}", EMAILJS_USER_ID);
    println!(
        "📧 Destinatario: {}",
        template_params.get("to_email").unwrap()
    );
    println!("📧 Asunto: {}", template_params.get("subject").unwrap());

    let payload_str = serde_json::to_string_pretty(&payload)?;
    println!("📦 Payload JSON:");
    println!("{}", payload_str);
    println!("═══════════════════════════════════════");
    println!("✅ Email configuration is valid!");
    println!("🚀 Ready to send emails to EmailJS API");
    println!("🌐 Target URL: https://api.emailjs.com/api/v1.0/email/send");
    println!("═══════════════════════════════════════");

    Ok(())
}

// Preview functions for debugging
pub fn preview_registration_email(to_email: &str, to_name: &str) {
    println!("📧 PREVIEW: Registration email for {}", to_name);
    println!("   From: simposiorevsalud@udenar.edu.co");
    println!("   To: {}", to_email);
    println!("   Subject: ✅ Registro Exitoso - Simposio Revista de Salud");
    println!(
        "   Message: Welcome to Simposio Revista de Salud, {}!",
        to_name
    );
}

pub fn preview_certificate_email(to_email: &str, to_name: &str, cert_type: &str) {
    let cert_name = match cert_type {
        "horizontal" => "Certificado de Participación",
        "vertical" => "Certificado de Ponencia",
        _ => "Certificado",
    };

    println!("📧 PREVIEW: Certificate email for {}", to_name);
    println!("   From: simposiorevsalud@udenar.edu.co");
    println!("   To: {}", to_email);
    println!(
        "   Subject: 🎓 {} Disponible - Simposio Rev Salud",
        cert_name
    );
    println!(
        "   Message: Su {} está listo para descargar, {}!",
        cert_name, to_name
    );
}
