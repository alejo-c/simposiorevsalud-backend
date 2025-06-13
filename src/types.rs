use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum Role {
    Staff,
    Attendee,
    Speaker { presentation: String },
}

impl Role {
    pub fn from(role: &str, presentation: String) -> Result<Role, &'static str> {
        println!("Role: {}", role);
        match role {
            "staff" => Ok(Role::Staff),
            "speaker" => Ok(Role::Speaker { presentation }),
            _ => Ok(Role::Attendee),
        }
    }

    pub fn extract(self: &Self) -> (String, String) {
        match self {
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
    pub fn from(attendance: &str) -> Result<Attendance, &'static str> {
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
    // pub role: Role,
    pub exp: usize,
}

#[derive(Deserialize, Debug)]
pub struct UserRequest {
    pub id: String,
    pub email: String,
    pub full_name: String,
    pub identification: String,
    pub password: String,
    pub roles: Vec<Role>,
    pub presentation: String,
    pub attendance: String,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub identification: String,
    pub full_name: String,
    pub roles: Vec<Role>,
    pub attendance: Attendance,
    pub cert_generated: CerticatesGeneration,
}

#[derive(Serialize)]
pub struct SimpleUserResponse {
    pub id: String,
    pub email: String,
    pub identification: String,
    pub full_name: String,
    pub roles: Vec<Role>,
}

impl From<User> for SimpleUserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            identification: user.identification,
            full_name: user.full_name,
            roles: user.roles,
        }
    }
}

#[derive(Serialize)]
pub struct PendingRequest {
    pub id: String,
    pub operation: String,
    pub user: SimpleUserResponse,
}

impl PendingRequest {
    pub fn new(operation: String, user: User) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            operation,
            user: SimpleUserResponse::from(user),
        }
    }
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            identification: user.identification,
            full_name: user.full_name,
            roles: user.roles,
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
    pub roles: Vec<Role>,
}

#[derive(Debug)]
pub struct User {
    pub id: String,
    pub email: String,
    pub identification: String,
    pub full_name: String,
    pub password: String,
    pub roles: Vec<Role>,
    pub attendance: Attendance,
    pub cert_generated: CerticatesGeneration,
}

impl User {
    pub fn new(
        email: String,
        identification: String,
        full_name: String,
        password: String,
        roles: Vec<Role>,
        attendance: Attendance,
    ) -> Self {
        User {
            id: Uuid::new_v4().to_string(),
            email,
            identification,
            full_name,
            password,
            roles,
            attendance,
            cert_generated: CerticatesGeneration::new(),
        }
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

// fn extract_field(row: &Row, name: &str) -> String {
//     row.get::<&str>(name).unwrap().to_string()
// }
