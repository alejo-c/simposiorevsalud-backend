use std::error::Error;

use serde::{Deserialize, Serialize};
use spin_sdk::sqlite::Row;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum Role {
    Webmaster,
    Staff,
    Attendee,
    Speaker { hours: u8 },
}

#[derive(Debug, Serialize)]
pub enum Attendance {
    Presential,
    Remote,
}

#[derive(Debug, Serialize)]
pub struct CerticatesGeneration {
    pub horizontal: bool,
    pub vertical: bool,
}

impl CerticatesGeneration {
    fn from(horizontal: bool, vertical: bool) -> Self {
        Self {
            horizontal,
            vertical,
        }
    }

    fn new() -> Self {
        Self::from(false, false)
    }
}

#[derive(Debug)]
pub struct User {
    pub id: String,
    pub email: String,
    pub identification: String,
    pub full_name: String,
    pub password: String,
    pub role: Role,
    pub attendance: Attendance,
    pub cert_generated: CerticatesGeneration,
}

impl User {
    pub fn new(
        id: String,
        email: String,
        identification: String,
        full_name: String,
        password: String,
        role: Role,
        attendance: Attendance,
    ) -> Self {
        User {
            id,
            email,
            identification,
            full_name,
            password,
            role,
            attendance,
            cert_generated: CerticatesGeneration::new(),
        }
    }

    pub fn from_row(row: &Row) -> Result<Self, Box<dyn Error>> {
        let role = row.get::<&str>("role").unwrap();
        let hours = row.get::<u8>("hours").unwrap();
        let attendance = row.get::<&str>("attendance").unwrap();

        Ok(User {
            id: extract_field(row, "id"),
            email: extract_field(row, "email"),
            identification: extract_field(row, "identification"),
            full_name: extract_field(row, "full_name"),
            password: extract_field(row, "password"),
            role: text_to_role(role, hours)?,
            attendance: text_to_attendance(attendance)?,
            cert_generated: CerticatesGeneration::from(
                row.get::<bool>("horiz_cert_generated").unwrap(),
                row.get::<bool>("vert_cert_generated").unwrap(),
            ),
        })
    }

    pub fn is_valid_password(password: &str) -> bool {
        // TODO: Define password guidelines
        password.len() >= 8
    }

    pub fn hash_password(password: &str) -> Result<String, &'static str> {
        // TODO: Hash password
        Ok(password.to_string())
    }

    pub fn verify_password(&self, password: String) -> bool {
        // TODO: Unhash self password and compare
        self.password == password
    }
}

pub fn role_to_text(role: Role) -> (String, u8) {
    match role {
        Role::Webmaster => ("webmaster".to_owned(), 0),
        Role::Staff => ("staff".to_owned(), 0),
        Role::Speaker { hours } => ("speaker".to_owned(), hours),
        _ => ("attendance".to_owned(), 0),
    }
}

pub fn text_to_role(role: &str, hours: u8) -> Result<Role, &'static str> {
    match role {
        "webmaster" => Ok(Role::Webmaster),
        "staff" => Ok(Role::Staff),
        "speaker" => Ok(Role::Speaker { hours }),
        "attendee" => Ok(Role::Attendee),
        _ => Err("Invalid role"),
    }
}

pub fn attendance_to_text(attendance: Attendance) -> String {
    match attendance {
        Attendance::Presential => "presential".to_owned(),
        _ => "remote".to_owned(),
    }
}

pub fn text_to_attendance(attendance: &str) -> Result<Attendance, &'static str> {
    match attendance {
        "presential" => Ok(Attendance::Presential),
        "remote" => Ok(Attendance::Remote),
        _ => Err("Invalid role"),
    }
}

fn extract_field(row: &Row, name: &str) -> String {
    row.get::<&str>(name).unwrap().to_string()
}
