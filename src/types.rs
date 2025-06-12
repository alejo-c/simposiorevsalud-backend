use serde::{Deserialize, Serialize};
use spin_sdk::sqlite::Row;
use std::error::Error;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum Role {
    Webmaster,
    Staff,
    Attendee,
    Speaker { presentation: String },
}

impl Role {
    pub fn parse(role: &str, presentation: String) -> Result<Role, &'static str> {
        println!("Role: {}", role);
        match role {
            "webmaster" => Ok(Role::Webmaster),
            "staff" => Ok(Role::Staff),
            "speaker" => Ok(Role::Speaker { presentation }),
            _ => Ok(Role::Attendee),
        }
    }

    pub fn to_string(self: &Self) -> (String, String) {
        match self {
            Role::Webmaster => ("webmaster".to_owned(), String::new()),
            Role::Staff => ("staff".to_owned(), String::new()),
            Role::Speaker { presentation } => ("speaker".to_owned(), presentation.to_owned()),
            _ => ("attendance".to_owned(), String::new()),
        }
    }
}

#[derive(Debug, Serialize)]
pub enum Attendance {
    Presential,
    Remote,
}

impl Attendance {
    pub fn parse(attendance: &str) -> Result<Attendance, &'static str> {
        match attendance {
            "presential" => Ok(Attendance::Presential),
            "remote" => Ok(Attendance::Remote),
            _ => Err("Invalid attendance"),
        }
    }

    pub fn to_string(self: &Self) -> String {
        match self {
            Attendance::Presential => "presential".to_owned(),
            _ => "remote".to_owned(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CerticatesGeneration {
    pub horizontal: bool,
    pub vertical: bool,
}

impl CerticatesGeneration {
    pub fn from(horizontal: bool, vertical: bool) -> Self {
        Self {
            horizontal,
            vertical,
        }
    }

    pub fn new() -> Self {
        Self::from(false, false)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: Role,
    pub exp: usize,
}

#[derive(Deserialize, Debug)]
pub struct UserRequest {
    pub id: String,
    pub email: String,
    pub full_name: String,
    pub identification: String,
    pub password: String,
    pub role: String,
    pub presentation: String,
    pub attendance: String,
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

#[derive(Serialize)]
pub struct SimpleUserResponse {
    pub id: String,
    pub email: String,
    pub identification: String,
    pub full_name: String,
    pub role: Role,
}

#[derive(Serialize)]
pub struct PendingRequest {
    pub id: String,
    pub operation: String,
    pub user: SimpleUserResponse,
    pub created_at: String,
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
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginResponse {
    pub email: String,
    pub full_name: String,
    pub role: Role,
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
        let presentation = row.get::<&str>("presentation").unwrap();
        let attendance = row.get::<&str>("attendance").unwrap();

        Ok(User {
            id: extract_field(row, "id"),
            email: extract_field(row, "email"),
            identification: extract_field(row, "identification"),
            full_name: extract_field(row, "full_name"),
            password: extract_field(row, "password"),
            role: Role::parse(role, presentation.to_string())?,
            attendance: Attendance::parse(attendance)?,
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

fn extract_field(row: &Row, name: &str) -> String {
    row.get::<&str>(name).unwrap().to_string()
}
