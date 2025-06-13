use anyhow::{Ok, Result};
use spin_sdk::sqlite::{Connection, Error, Row, Value};
use time::{format_description::well_known::Iso8601, OffsetDateTime};

use crate::types::{
    Attendance, CerticatesGeneration, PendingRequest, Role, SimpleUserResponse, User,
};

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

fn insert_role(role: Role, user_id: String) -> Result<()> {
    let (role_name, presentation) = role.extract();

    open_connection()?.execute(
        "INSERT INTO user_role (user_id, role, presentation) VALUES(?, ?, ?)",
        &[
            Value::Text(user_id),
            Value::Text(role_name),
            Value::Text(presentation),
        ],
    )?;

    Ok(())
}

pub fn insert_user(user: User) -> Result<()> {
    let conn = open_connection()?;
    let attendance = user.attendance.to_string();

    let params = [
        Value::Text(user.id.clone()),
        Value::Text(user.email.clone()),
        Value::Text(user.identification.clone()),
        Value::Text(user.full_name.clone()),
        Value::Text(user.password.clone()),
        Value::Text(attendance),
    ];

    conn.execute(
        "INSERT INTO user (id, email, identification, full_name, password, attendance)
        VALUES (?, ?, ?, ?, ?, ?)",
        &params,
    )?;

    for role in user.roles.clone().into_iter() {
        insert_role(role.to_owned(), user.id.clone())?;
    }

    insert_pending_request(PendingRequest::new(
        String::from("User register"),
        user,
    ))?;
    Ok(())
}

pub fn extract_user(row: &Row) -> Result<User> {
    let attendance = row.get::<&str>("attendance").unwrap();
    let user_id = extract_field(row, "id");
    let roles = get_user_roles((&user_id).to_owned())?;

    Ok(User {
        id: user_id,
        email: extract_field(row, "email"),
        identification: extract_field(row, "identification"),
        full_name: extract_field(row, "full_name"),
        password: extract_field(row, "password"),
        roles: roles,
        attendance: Attendance::from(attendance).ok().unwrap(),
        cert_generated: CerticatesGeneration::from(
            row.get::<bool>("horiz_cert_generated").unwrap(),
            row.get::<bool>("vert_cert_generated").unwrap(),
        ),
    })
}

pub fn get_user_roles(user_id: String) -> Result<Vec<Role>> {
    let rowset = open_connection()?.execute(
        "SELECT * FROM user_role WHERE user_id = ?",
        &[Value::Text(user_id)],
    )?;

    let roles: Vec<Role> = rowset
        .rows()
        .map(|row| {
            let role = extract_field(&row, "role");
            let presentation = extract_field(&row, "presentation");
            Role::from(role.as_str(), presentation).ok().unwrap()
        })
        .collect();

    Ok(roles)
}

pub fn get_user_by_email(email: String) -> Result<Option<User>> {
    let res =
        open_connection()?.execute("SELECT * FROM user WHERE email = ?", &[Value::Text(email)])?;

    let row = &res.rows().next();
    match row {
        Some(row) => {
            let user = extract_user(row).unwrap();
            Ok(Some(user))
        }
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
        Some(row) => Ok(Some(extract_user(row).unwrap())),
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
    Ok(extract_user(row).unwrap())
}

pub fn get_all_users() -> Result<Vec<User>> {
    let conn = open_connection()?;
    let rowset = conn.execute("SELECT * FROM user", &[])?;

    let users = rowset
        .rows()
        .map(|row| extract_user(&row).unwrap())
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

pub fn update_roles(new_roles: Vec<Role>, user_id: &String) -> Result<()> {
    let conn = open_connection()?;
    let user = get_user_by_id(user_id)?;

    for role in new_roles.into_iter() {
        let (role_name, presentation) = role.extract();
        if user.roles.contains(&role) {
            conn.execute(
                "INSERT INTO user_role(user_id, role, presentation) VALUES (?, ?, ?)",
                &[
                    Value::Text(user_id.to_owned()),
                    Value::Text(role_name),
                    Value::Text(presentation),
                ],
            )?;
        } else {
            conn.execute(
                "DELETE FROM user_role WHERE user_id = ? role = ?",
                &[Value::Text(user_id.to_owned()), Value::Text(role_name)],
            )?;
        }
    }
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
            let user_id = extract_field(&row, "user_id");

            let user = SimpleUserResponse {
                id: (&user_id).to_owned(),
                email: extract_field(&row, "user_email"),
                identification: extract_field(&row, "user_identification"),
                full_name: extract_field(&row, "full_name"),
                roles: get_user_roles(user_id).ok().unwrap(),
            };

            PendingRequest {
                id: extract_field(&row, "id"),
                operation: extract_field(&row, "operation"),
                user: user,
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
