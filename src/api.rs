use anyhow::{anyhow, Ok, Result};
use cookie::Cookie;
use jsonwebtoken::{decode, encode, errors::Error, DecodingKey, EncodingKey, Header, Validation};
use serde_json::json;
use spin_sdk::{
    http::{
        conversions::{IntoBody, IntoStatusCode},
        IntoResponse, Params, Request, Response,
    },
    variables,
};
use time::{Duration, OffsetDateTime};

use crate::{
    db::{self},
    types::{
        Attendance, Claims, LoginRequest, PendingRequest, Role, User, UserRequest, UserResponse,
    },
};

fn extract_token_from_cookie(req: &Request) -> Result<String> {
    let cookie_header = req
        .headers()
        .find(|(name, _)| name.eq_ignore_ascii_case("cookie"))
        .map(|(_, value)| value.as_str().unwrap_or(""))
        .unwrap_or("");

    Cookie::split_parse(cookie_header)
        .find_map(|c| {
            c.ok().and_then(|c| {
                if c.name() == "token" {
                    Some(c.value().to_string())
                } else {
                    None
                }
            })
        })
        .ok_or(anyhow!("Token cookie not found"))
}

// fn generate_jwt(user_id: String, user_role: &Role) -> Result<String> {
fn generate_jwt(user_id: String) -> Result<String> {
    let expiration = (OffsetDateTime::now_utc() + Duration::hours(1)).unix_timestamp() as usize;
    let secret = variables::get("jwt").unwrap();

    let claims = Claims {
        sub: user_id,
        // role: user_role.to_owned(),
        exp: expiration,
    };

    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )?)
}

fn verify_token(token: &str) -> Result<Claims, Error> {
    let secret_key = variables::get("jwt_secret_key").unwrap();

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret_key.as_ref()),
        &Validation::new(jsonwebtoken::Algorithm::HS256),
    )
    .map(|data| data.claims)
}

fn protected<F>(req: &Request, handler: F) -> Result<Response>
where
    F: FnOnce(String, Claims, User) -> Result<Response>,
{
    let token = extract_token_from_cookie(&req)?;
    let claims = verify_token(&token)?;
    let user = db::get_user_by_id(&claims.sub)?;
    handler(token, claims, user)
}

fn build_response(
    status: impl IntoStatusCode,
    key: impl Into<String>,
    value: impl Into<String>,
    body: impl IntoBody,
) -> Response {
    Response::builder()
        .status(status)
        .header(key, value)
        .body(body)
        .build()
}

fn is_valid_for_update(new: &String, prev: String) -> bool {
    prev.ne(new) && !new.is_empty()
}

pub fn is_valid_email(email: &str) -> bool {
    email.contains('@') && email.contains('.')
}

// Routes

pub fn register_user(req: Request, _params: Params) -> Result<impl IntoResponse> {
    let register_data: UserRequest = serde_json::from_slice(req.body())?;
    let user = db::get_user_by_email((&register_data.email).to_owned()).ok();

    if let Some(_) = user.unwrap() {
        return Ok(Response::new(400, "Email ya registrado"));
    }

    let identification =
        db::get_user_by_identification((&register_data.identification).to_owned()).ok();
    if let Some(_) = identification.unwrap() {
        return Ok(Response::new(400, "Identificación ya registrada"));
    }
    if !is_valid_email(&register_data.email) {
        return Ok(Response::new(400, "Formato de email inválido"));
    }
    if !User::is_valid_password(&register_data.password) {
        return Ok(Response::new(400, "Contraseña inválida"));
    }

    let hashed_password = User::hash_password(&register_data.password.as_str()).unwrap();
    let attendance = Attendance::from(&register_data.attendance).unwrap();

    let user = User::new(
        register_data.email.to_string(),
        register_data.identification.to_string(),
        register_data.full_name.to_string(),
        hashed_password,
        register_data.roles,
        attendance,
    );

    db::insert_user(user)?;

    Ok(Response::new(
        201,
        "Usuario registrado exitosamente. Email será enviado.",
    ))
}

// Also update your user_login function:
pub fn login_user(req: Request, _params: Params) -> Result<impl IntoResponse> {
    let creds: LoginRequest = serde_json::from_slice(&req.body())?;
    let user = match db::get_user_by_email(creds.email)? {
        Some(user) => user,
        None => return Ok(Response::new(400, "User not registered")),
    };

    if !user.verify_password(creds.password.to_string()) {
        return Ok(Response::new(400, "Error: contraseña incorrecta"));
    }

    let role = user.roles;
    // let token = generate_jwt(user.id, &role)?;
    let token = generate_jwt(user.id)?;
    let cookie = format!(
        "token={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        token, 3600
    );

    let response_body = serde_json::json!({
        "message": "Usuario logueado exitosamente",
        "user": {
            "email": user.email,
            "full_name": user.full_name,
            "role": &role
        }
    })
    .to_string();

    Ok(Response::builder()
        .status(200)
        .header(
            "Access-Control-Allow-Origin",
            "https://simposiorevsalud.univsalud.online",
        )
        .header(
            "Access-Control-Allow-Methods",
            "GET, POST, PUT, DELETE, OPTIONS",
        )
        .header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, Cookie",
        )
        .header("Access-Control-Allow-Credentials", "true")
        .header("Set-Cookie", cookie)
        .header("Content-Type", "application/json")
        .body(response_body)
        .build())
}

pub fn logout_user(req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |token, claims, user| {
        let expires_at = OffsetDateTime::from_unix_timestamp(claims.exp as i64)?;

        db::revoke_token(&token, expires_at, user.id)?;
        let clear_cookie = "token=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";

        Ok(build_response(
            200,
            "Set-Cookie",
            clear_cookie,
            serde_json::to_vec(&json!({"status": 200, "message": "Logged out"}))?,
        ))
    })?)
}

pub fn get_user_profile(req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        let user = UserResponse::from(user);

        Ok(build_response(
            200,
            "Content-Type",
            "application/json",
            serde_json::to_vec(&user)?,
        ))
    })?)
}

pub fn admin_get_user(req: Request, _param: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        if !user.roles.iter().any(|role| *role == Role::Staff) {
            return Ok(Response::new(403, "Insufficient permissions"));
        }

        let user = UserResponse::from(user);
        Ok(build_response(
            200,
            "Content-Type",
            "application/json",
            serde_json::to_vec(&user)?,
        ))
    })?)
}

pub fn update_user(req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        let user_req: UserRequest = serde_json::from_slice(&req.body())?;

        if is_valid_for_update(&user_req.email, user.email) {
            db::update_email(&user_req.email, &user_req.id)?;
        }
        if is_valid_for_update(&user_req.password, user.password) {
            db::update_password(&user_req.password, &user_req.id)?;
        }
        if !user_req.roles.is_empty() {
            db::update_roles((&user_req.roles).to_owned(), &user_req.id)?;
        }
        if !user_req.attendance.is_empty() && Attendance::from(&user_req.attendance).is_ok() {
            db::update_attendance(&user_req.attendance, &user_req.id)?;
        }

        Ok(Response::new(200, "User updated"))
    })?)
}

pub fn admin_update_user(req: Request, _param: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        if !user.roles.iter().any(|role| *role == Role::Staff) {
            return Ok(Response::new(403, "Insufficient permissions"));
        }

        let user_req: UserRequest = serde_json::from_slice(&req.body())?;

        if is_valid_for_update(&user_req.email, user.email) {
            db::update_email(&user_req.email, &user_req.id)?;
        }
        if is_valid_for_update(&user_req.full_name, user.full_name) {
            db::update_full_name(&user_req.full_name, &user_req.id)?;
        }
        if is_valid_for_update(&user_req.identification, user.identification) {
            db::update_full_name(&user_req.identification, &user_req.id)?;
        }
        if is_valid_for_update(&user_req.password, user.password) {
            db::update_password(&user_req.password, &user_req.id)?;
        }
        if !user_req.roles.is_empty() {
            db::update_roles(user_req.roles, &user_req.id)?;
        }
        if !user_req.attendance.is_empty() && Attendance::from(&user_req.attendance).is_ok() {
            db::update_attendance(&user_req.attendance, &user_req.id)?;
        }

        Ok(Response::new(200, "User updated"))
    })?)
}

pub fn delete_user(req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        let body_bytes = req.body().to_vec();

        let user_id = match String::from_utf8(body_bytes) {
            core::result::Result::Ok(s) => s.trim().to_string(),
            Err(_) => {
                return Ok(Response::new(400, "Invalid UTF-8 in request body"));
            }
        };

        if user.id.ne(user_id.as_str()) {
            return Ok(Response::new(400, "Insufficient permissions"));
        }
        db::delete_user(user.id)?;

        Ok(Response::new(200, "User deleted"))
    })?)
}

pub fn admin_delete_user(req: Request, _param: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        if !user.roles.iter().any(|role| *role == Role::Staff) {
            return Ok(Response::new(403, "Insufficient permissions"));
        }

        let body_bytes = req.body().to_vec();
        let user_id = match String::from_utf8(body_bytes) {
            core::result::Result::Ok(s) => s.trim().to_string(),
            Err(_) => {
                return Ok(Response::new(400, "Invalid UTF-8 in request body"));
            }
        };

        db::delete_user(user_id)?;
        Ok(Response::new(200, "User deleted"))
    })?)
}

pub fn generate_horiz_cert(req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        db::update_horiz_cert_status(user.id.as_str())?;

        // Log that email would be sent
        println!(
            "📧 Certificate notification would be sent to: {} ({})",
            user.email, user.full_name
        );

        Ok(Response::new(
            200,
            "Certificado horizontal generado. Notificación programada.",
        ))
    })?)
}

pub fn generate_vert_cert(req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        db::update_vert_cert_status(user.id.as_str())?;

        // Log that email would be sent
        println!(
            "📧 Certificate notification would be sent to: {} ({})",
            user.email, user.full_name
        );

        Ok(Response::new(
            200,
            "Certificado vertical generado. Notificación programada.",
        ))
    })?)
}

pub fn admin_generate_horiz_cert(req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, admin_user| {
        if !admin_user.roles.iter().any(|role| *role == Role::Staff) {
            return Ok(Response::new(403, "Insufficient permissions"));
        }

        let body_bytes = req.body().to_vec();
        let user_id = match String::from_utf8(body_bytes) {
            core::result::Result::Ok(s) => s.trim().to_string(),
            Err(_) => {
                return Ok(Response::new(
                    400,
                    "UTF-8 inválido en el cuerpo de la solicitud",
                ));
            }
        };

        db::update_horiz_cert_status(user_id.as_str())?;

        // Get user info for email notification
        if let core::result::Result::Ok(target_user) = db::get_user_by_id(&user_id) {
            println!(
                "📧 Certificate notification would be sent by admin to: {} ({})",
                target_user.email, target_user.full_name
            );
        }

        Ok(Response::new(
            200,
            "Certificado horizontal generado por administrador",
        ))
    })?)
}

pub fn admin_generate_vert_cert(req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, admin_user| {
        if !admin_user.roles.iter().any(|role| *role == Role::Staff) {
            return Ok(Response::new(403, "Insufficient permissions"));
        }

        let body_bytes = req.body().to_vec();
        let user_id = match String::from_utf8(body_bytes) {
            core::result::Result::Ok(s) => s.trim().to_string(),
            Err(_) => {
                return Ok(Response::new(
                    400,
                    "UTF-8 inválido en el cuerpo de la solicitud",
                ));
            }
        };

        db::update_vert_cert_status(user_id.as_str())?;

        // Get user info for email notification
        if let core::result::Result::Ok(target_user) = db::get_user_by_id(&user_id) {
            println!(
                "📧 Certificate notification would be sent by admin to: {} ({})",
                target_user.email, target_user.full_name
            );
        }

        Ok(Response::new(
            200,
            "Certificado vertical generado por administrador",
        ))
    })?)
}

pub fn list_users(req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        if !user.roles.iter().any(|role| *role == Role::Staff) {
            return Ok(Response::new(403, "Insufficient permissions"));
        }

        let users: Vec<UserResponse> = db::get_all_users()?
            .into_iter()
            .map(UserResponse::from)
            .collect();

        Ok(build_response(
            200,
            "Content-Type",
            "application/json",
            serde_json::to_vec(&users)?,
        ))
    })?)
}

pub fn list_pending_requests(_req: Request, _params: Params) -> Result<impl IntoResponse> {
    let pending_requests: Vec<PendingRequest> = db::get_pending_requests()?;

    Ok(build_response(
        200,
        "Content-Type",
        "application/json",
        serde_json::to_vec(&pending_requests)?,
    ))
}

pub fn delete_pending_request(req: Request, _params: Params) -> Result<impl IntoResponse> {
    let body_bytes = req.body().to_vec();

    let pending_request_id = match String::from_utf8(body_bytes) {
        core::result::Result::Ok(s) => s.trim().to_string(),
        Err(_) => {
            return Ok(Response::new(400, "Invalid UTF-8 in request body"));
        }
    };

    db::delete_pending_request(pending_request_id)?;
    Ok(Response::new(200, "Pending request deleted successfully"))
}
