pub mod api;
pub mod auth;
pub mod db;
pub mod email;

use spin_sdk::{
    http::{Request, Response, Router},
    http_component,
};

#[http_component]
fn handle_simposiorevsalud(req: Request) -> Response {
    let mut router = Router::new();

    // Public routes
    router.post("/api/register", api::user_register);
    router.put("/api/login", api::user_login);

    // Private routes
    router.put("/api/logout", api::user_logout);

    router.post("/api/user/profile", api::user_profile);
    router.put("/api/user/update", api::user_update);
    router.delete("/api/user/delete", api::user_delete);

    router.put("/api/user/horiz-cert", api::generate_horiz_cert);
    router.put("/api/user/vert-cert", api::generate_vert_cert);

    router.post("/api/admin/users", api::list_users);
    router.post("/api/admin/user", api::show_user);
    router.put("/api/admin/update", api::admin_user_update);
    router.put("/api/admin/horiz-cert", api::admin_generate_horiz_cert);
    router.put("/api/admin/horiz-cert", api::admin_generate_vert_cert);
    router.delete("/api/admin/delete", api::admin_user_delete);

    router.handle(req)
}
