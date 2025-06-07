use anyhow::{Ok, Result};
use spin_sdk::sqlite::{Connection, Error, Row, Value};
use time::{format_description::well_known::Iso8601, OffsetDateTime, UtcDateTime};

use crate::auth::{attendance_to_text, role_to_text, User};

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

    let (role, hours) = role_to_text(user.role);
    let attendance = attendance_to_text(user.attendance);

    let params = [
        Value::Text(user.id),
        Value::Text(user.email),
        Value::Text(user.identification),
        Value::Text(user.full_name),
        Value::Text(user.password),
        Value::Text(role),
        Value::Integer(hours.into()),
        Value::Text(attendance),
    ];

    conn.execute(
        "INSERT INTO user (id, email, identification, full_name, password, role, hours, attendance)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        &params,
    )?;

    Ok(())
}

pub fn get_user_by_email(email: String) -> Result<User> {
    let conn = open_connection()?;
    let res = conn.execute("SELECT * FROM user WHERE email = ?", &[Value::Text(email)])?;

    let row = &res.rows().next().unwrap();
    Ok(User::from_row(row).unwrap())
}

pub fn get_user_by_identification(identification: String) -> Result<User> {
    let conn = open_connection()?;
    let res = conn.execute(
        "SELECT * FROM user WHERE identification = ?",
        &[Value::Text(identification)],
    )?;

    let row = &res.rows().next().unwrap();
    Ok(User::from_row(row).unwrap())
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

pub fn update_role(new_role: &String, new_hours: &u8, user_id: &String) -> Result<()> {
    open_connection()?.execute(
        "UPDATE user SET role = ?, hours = ?  WHERE id = ?",
        &[
            Value::Text(new_role.to_owned()),
            Value::Integer(new_hours.to_owned().into()),
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

pub fn insert_log(email: String, operation: String) -> Result<()> {
    let date_time = UtcDateTime::now().to_string();

    open_connection()?.execute(
        "INSERT INTO log (user_id, operation, created_at) VALUES (?, ?, ?)",
        &[
            Value::Text(email),
            Value::Text(date_time),
            Value::Text(operation),
        ],
    )?;
    Ok(())
}

// Others

pub fn extract_field(row: &Row, name: &str) -> String {
    row.get::<&str>(name).unwrap().to_string()
}
