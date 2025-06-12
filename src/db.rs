use anyhow::{Ok, Result};
use spin_sdk::sqlite::{Connection, Error, Row, Value};
use time::{format_description::well_known::Iso8601, OffsetDateTime};

use crate::types::{PendingRequest, Role, SimpleUserResponse, User};

fn open_connection() -> Result<Connection, Error> {
    Connection::open_default()
}

pub fn is_token_valid(token: &str) -> Result<bool> {
    let conn = open_connection()?;
    let rowset = conn.execute(
        "SELECT 1 FROM revoked_tokens WHERE token = ? AND expires_at > datetime('now')",
        &[Value::Text(token.to_string())],
    )?;

    Ok(rowset.rows().count() == 0)
}

pub fn revoke_token(token: &str, expires_at: OffsetDateTime, user_id: String) -> Result<()> {
    let conn = open_connection()?;
    let exp = expires_at.format(&Iso8601::DEFAULT)?;

    conn.execute(
        "INSERT INTO revoked_tokens (token, expires_at, user_id) VALUES (?, ?, ?)",
        &[
            Value::Text(token.to_string()),
            Value::Text(exp),
            Value::Text(user_id),
        ],
    )?;

    Ok(())
}

pub fn insert_user(user: User) -> Result<()> {
    let conn = open_connection()?;

    let (role, presentation) = user.role.to_string();
    let attendance = user.attendance.to_string();

    let params = [
        Value::Text(user.id),
        Value::Text(user.email),
        Value::Text(user.identification),
        Value::Text(user.full_name),
        Value::Text(user.password),
        Value::Text(role),
        Value::Text(presentation),
        Value::Text(attendance),
    ];

    conn.execute(
        "INSERT INTO user (id, email, identification, full_name, password, role, presentation, attendance)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        &params,
    )?;

    Ok(())
}

pub fn get_user_by_email(email: String) -> Result<Option<User>> {
    let conn = open_connection()?;
    let res = conn.execute("SELECT * FROM user WHERE email = ?", &[Value::Text(email)])?;

    let row = &res.rows().next();
    match row {
        Some(row) => Ok(Some(User::from_row(row).unwrap())),
        None => Ok(None),
    }
}

pub fn get_user_by_identification(identification: String) -> Result<Option<User>> {
    let conn = open_connection()?;
    let res = conn.execute(
        "SELECT * FROM user WHERE identification = ?",
        &[Value::Text(identification)],
    )?;

    let row = &res.rows().next();
    match row {
        Some(row) => Ok(Some(User::from_row(row).unwrap())),
        None => Ok(None),
    }
}

pub fn get_user_by_id(id: &str) -> Result<User> {
    let conn = open_connection()?;

    let res = conn.execute(
        "SELECT * FROM user WHERE id = ?",
        &[Value::Text(id.to_string())],
    )?;

    let row = &res.rows().next().unwrap();
    Ok(User::from_row(row).unwrap())
}

pub fn get_all_users() -> Result<Vec<User>> {
    let conn = open_connection()?;
    let rowset = conn.execute("SELECT * FROM user", &[])?;

    let users = rowset
        .rows()
        .map(|row| User::from_row(&row).unwrap())
        .collect();
    Ok(users)
}

pub fn update_email(new_email: &String, user_id: &String) -> Result<()> {
    open_connection()?.execute(
        "UPDATE user SET email = ? WHERE id = ?",
        &[
            Value::Text(new_email.to_owned()),
            Value::Text(user_id.to_owned()),
        ],
    )?;
    Ok(())
}

pub fn update_full_name(new_full_name: &String, user_id: &String) -> Result<()> {
    open_connection()?.execute(
        "UPDATE user SET full_name = ? WHERE id = ?",
        &[
            Value::Text(new_full_name.to_owned()),
            Value::Text(user_id.to_owned()),
        ],
    )?;
    Ok(())
}

pub fn update_identification(new_identification: &String, user_id: &String) -> Result<()> {
    open_connection()?.execute(
        "UPDATE user SET identification = ? WHERE id = ?",
        &[
            Value::Text(new_identification.to_owned()),
            Value::Text(user_id.to_owned()),
        ],
    )?;
    Ok(())
}

pub fn update_password(new_password: &String, user_id: &String) -> Result<()> {
    open_connection()?.execute(
        "UPDATE user SET password = ? WHERE id = ?",
        &[
            Value::Text(new_password.to_owned()),
            Value::Text(user_id.to_owned()),
        ],
    )?;
    Ok(())
}

pub fn update_role(new_role: &String, new_presentation: &String, user_id: &String) -> Result<()> {
    open_connection()?.execute(
        "UPDATE user SET role = ?, hours = ?  WHERE id = ?",
        &[
            Value::Text(new_role.to_owned()),
            Value::Text(new_presentation.to_owned()),
            Value::Text(user_id.to_owned()),
        ],
    )?;
    Ok(())
}

pub fn update_attendance(new_attendance: &String, user_id: &String) -> Result<()> {
    open_connection()?.execute(
        "UPDATE user SET attendance = ? WHERE id = ?",
        &[
            Value::Text(new_attendance.to_owned()),
            Value::Text(user_id.to_owned()),
        ],
    )?;
    Ok(())
}

pub fn update_horiz_cert_status(user_id: &str) -> Result<()> {
    open_connection()?.execute(
        "UPDATE user SET horiz_cert_generated = 1 WHERE id = ?",
        &[Value::Text(user_id.to_string())],
    )?;
    Ok(())
}

pub fn update_vert_cert_status(user_id: &str) -> Result<()> {
    open_connection()?.execute(
        "UPDATE user SET vert_cert_generated = 1 WHERE id = ?",
        &[Value::Text(user_id.to_string())],
    )?;
    Ok(())
}

pub fn delete_user(user_id: String) -> Result<()> {
    open_connection()?.execute("DELETE user WHERE id = ?", &[Value::Text(user_id)])?;
    Ok(())
}

pub fn list_logs() -> Result<Vec<(u8, String, String, String)>> {
    let conn = open_connection()?;
    let rowset = conn.execute("SELECT * FROM log", &[])?;

    let logs: Vec<(u8, String, String, String)> = rowset
        .rows()
        .map(|row| {
            (
                row.get::<u8>("log_id").unwrap(),
                extract_field(&row, "user_id"),
                extract_field(&row, "operation"),
                extract_field(&row, "created_at"),
            )
        })
        .collect();

    Ok(logs)
}

pub fn insert_pending_request(pending_request: PendingRequest) -> Result<()> {
    open_connection()?.execute(
        "INSERT INTO pending_request (id, operation, user_id)",
        &[
            Value::Text(pending_request.id),
            Value::Text(pending_request.operation),
            Value::Text(pending_request.user.id),
        ],
    )?;

    Ok(())
}

pub fn get_pending_requests() -> Result<Vec<PendingRequest>> {
    let rowset = open_connection()?.execute("SELECT * from pending_request", &[])?;

    let pending_requests: Vec<PendingRequest> = rowset
        .rows()
        .map(|row| {
            let role = extract_field(&row, "user_role");
            let presentation = extract_field(&row, "user_presentation");

            let user = SimpleUserResponse {
                id: extract_field(&row, "user_id"),
                email: extract_field(&row, "user_email"),
                identification: extract_field(&row, "user_identification"),
                full_name: extract_field(&row, "full_name"),
                role: Role::parse(role.as_str(), presentation).unwrap(),
            };

            PendingRequest {
                id: extract_field(&row, "id"),
                operation: extract_field(&row, "operation"),
                user: user,
                created_at: extract_field(&row, "created_at"),
            }
        })
        .collect();

    Ok(pending_requests)
}

pub fn delete_pending_request(pending_request_id: String) -> Result<()> {
    open_connection()?.execute(
        "DELETE pending_request WHERE id = ?",
        &[Value::Text(pending_request_id)],
    )?;
    Ok(())
}

pub fn insert_log(email: String, operation: String) -> Result<()> {
    open_connection()?.execute(
        "INSERT INTO log (user_id, operation) VALUES (?, ?)",
        &[Value::Text(email), Value::Text(operation)],
    )?;

    Ok(())
}

fn extract_field(row: &Row, name: &str) -> String {
    row.get::<&str>(name).unwrap().to_string()
}
