use anyhow::{anyhow, Ok, Result};
use cookie::Cookie;
use jsonwebtoken::{decode, encode, errors::Error, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use spin_sdk::{
    http::{
        conversions::{IntoBody, IntoStatusCode},
        IntoResponse, Params, Request, Response,
    },
    variables,
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    auth::{text_to_attendance, text_to_role, Attendance, CerticatesGeneration, Role, User},
    db::{self},
    email,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: Role,
    pub exp: usize,
}

#[derive(Deserialize)]
struct UserRequest {
    id: String,
    email: String,
    full_name: String,
    identification: String,
    password: String,
    role: String,
    hours: u8,
    attendance: String,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub identification: String,
    pub full_name: String,
    pub role: Role,
    pub attendance: Attendance,
    pub cert_generated: CerticatesGeneration,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            identification: user.identification,
            full_name: user.full_name,
            role: user.role,
            attendance: user.attendance,
            cert_generated: user.cert_generated,
        }
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
struct LoginResponse {
    pub email: String,
    pub full_name: String,
    pub role: Role,
}

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

fn generate_jwt(user_id: String, user_role: &Role) -> Result<String> {
    let expiration = (OffsetDateTime::now_utc() + Duration::hours(1)).unix_timestamp() as usize;
    let secret = variables::get("jwt").unwrap();

    let claims = Claims {
        sub: user_id,
        role: user_role.to_owned(),
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
    // TODO: Add new email only constraint
    email.contains('@') && email.contains('.')
}

// Routes

pub fn user_register(req: Request, _params: Params) -> Result<impl IntoResponse> {
    let register_data: UserRequest = serde_json::from_slice(req.body())?;

    if !db::get_user_by_email((&register_data.email).to_owned()).is_ok() {
        return Ok(Response::new(400, "Email already registered"));
    }
    if !db::get_user_by_identification((&register_data.identification).to_owned()).is_ok() {
        return Ok(Response::new(400, "identification already registered"));
    }
    if !is_valid_email(&register_data.email) {
        return Ok(Response::new(400, "Invalid email format"));
    }
    if !User::is_valid_password(&register_data.password) {
        return Ok(Response::new(400, "Invalid password"));
    }

    let hashed_password = User::hash_password(&register_data.password.as_str()).unwrap();
    let role = text_to_role(&register_data.role, 0).unwrap();
    let attendance = text_to_attendance(&register_data.attendance).unwrap();

    let user = User::new(
        Uuid::new_v4().to_string(),
        register_data.email.to_string(),
        register_data.identification.to_string(),
        register_data.full_name.to_string(),
        hashed_password,
        role,
        attendance,
    );

    db::insert_user(user)?;

    match email::send_quick_html_email(&register_data.email, "Usuario registrado todo()!", html!)
    {
        core::result::Result::Ok(_) => Ok(Response::new(201, "User regsitered successfully")),
        Err(e) => Ok(Response::new(400, format!("Error: {}", e))),
    }
}

pub fn user_login(req: Request, _params: Params) -> Result<impl IntoResponse> {
    let creds: LoginRequest = serde_json::from_slice(&req.body())?;
    let user = db::get_user_by_email(creds.email)?;

    if !user.verify_password(creds.password.to_string()) {
        return Ok(Response::new(400, "Error: incorrect password"));
    }

    let role = user.role;
    let token = generate_jwt(user.id, &role)?;
    let cookie = format!(
        "token={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        token, 3600
    );

    Ok(Response::builder()
        .status(200)
        .header("Set-Cookie", cookie)
        .body(serde_json::json!("User logged successfully").to_string())
        .header("Content-Type", "application/json")
        .build())
}

pub fn user_logout(req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |token, claims, user| {
        let expires_at = OffsetDateTime::from_unix_timestamp(claims.exp as i64)?;

        db::revoke_token(&token, expires_at, user.id)?;
        let clear_cookie = "token=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
        let res = json!({"status": "success", "message": "Logged out"});

        Ok(build_response(
            200,
            "Set-Cookie",
            clear_cookie,
            serde_json::to_vec(&res)?,
        ))
    })?)
}

pub fn user_profile(req: Request, _params: Params) -> Result<impl IntoResponse> {
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

pub fn show_user(req: Request, _param: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        match user.role {
            Role::Webmaster | Role::Staff => {}
            _ => return Ok(Response::new(403, "Insufficient permissions")),
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
pub fn user_update(req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        let user_req: UserRequest = serde_json::from_slice(&req.body())?;

        // if user.id.ne(&user_req.id) {
        //     return Ok(Response::new(403, "Insufficient permissions"));
        // }
        if is_valid_for_update(&user_req.email, user.email) {
            db::update_email(&user_req.email, &user_req.id)?;
        }
        if is_valid_for_update(&user_req.password, user.password) {
            db::update_password(&user_req.password, &user_req.id)?;
        }
        if !user_req.role.is_empty()
            && text_to_role(&user_req.role, (&user_req.hours).to_owned()).is_ok()
        {
            db::update_role(&user_req.role, &user_req.hours, &user_req.id)?;
        }
        if !user_req.attendance.is_empty() && text_to_attendance(&user_req.attendance).is_ok() {
            db::update_attendance(&user_req.attendance, &user_req.id)?;
        }

        Ok(Response::new(200, "User updated"))
    })?)
}

pub fn admin_user_update(req: Request, _param: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        match user.role {
            Role::Webmaster | Role::Staff => {}
            _ => return Ok(Response::new(403, "Insufficient permissions")),
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
        if !user_req.role.is_empty()
            && text_to_role(&user_req.role, (&user_req.hours).to_owned()).is_ok()
        {
            db::update_role(&user_req.role, &user_req.hours, &user_req.id)?;
        }
        if !user_req.attendance.is_empty() && text_to_attendance(&user_req.attendance).is_ok() {
            db::update_attendance(&user_req.attendance, &user_req.id)?;
        }

        Ok(Response::new(200, "User updated"))
    })?)
}

pub fn user_delete(req: Request, _params: Params) -> Result<impl IntoResponse> {
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

pub fn admin_user_delete(req: Request, _param: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        match user.role {
            Role::Webmaster | Role::Staff => {}
            _ => return Ok(Response::new(403, "Insufficient permissions")),
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

        Ok(Response::new(200, "Horizontal certificate generated"))
    })?)
}

pub fn admin_generate_horiz_cert(req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        match user.role {
            Role::Webmaster | Role::Staff => {}
            _ => return Ok(Response::new(403, "Insufficient permissions")),
        }

        let body_bytes = req.body().to_vec();
        let user_id = match String::from_utf8(body_bytes) {
            core::result::Result::Ok(s) => s.trim().to_string(),
            Err(_) => {
                return Ok(Response::new(400, "Invalid UTF-8 in request body"));
            }
        };
        db::update_horiz_cert_status(user_id.as_str())?;

        Ok(Response::new(200, "Horizontal certificate generated"))
    })?)
}

pub fn generate_vert_cert(req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        db::update_vert_cert_status(user.id.as_str())?;

        Ok(Response::new(200, "Vertical certificate generated"))
    })?)
}

pub fn admin_generate_vert_cert(req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        match user.role {
            Role::Webmaster | Role::Staff => {}
            _ => return Ok(Response::new(403, "Insufficient permissions")),
        }

        let body_bytes = req.body().to_vec();
        let user_id = match String::from_utf8(body_bytes) {
            core::result::Result::Ok(s) => s.trim().to_string(),
            Err(_) => {
                return Ok(Response::new(400, "Invalid UTF-8 in request body"));
            }
        };
        db::update_vert_cert_status(user_id.as_str())?;

        Ok(Response::new(200, "Vertical certificate generated"))
    })?)
}

pub fn list_users(req: Request, _params: Params) -> Result<impl IntoResponse> {
    Ok(protected(&req, |_token, _claims, user| {
        match user.role {
            Role::Webmaster | Role::Staff => {}
            _ => return Ok(Response::new(403, "Insufficient permissions")),
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
