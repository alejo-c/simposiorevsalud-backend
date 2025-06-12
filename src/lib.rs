pub mod api;
pub mod db;
pub mod types;

use spin_sdk::{
    http::{Request, Response, Router},
    http_component,
};

#[http_component]
fn handle_simposiorevsalud(req: Request) -> Response {
    let mut router = Router::new();

    // Public routes
    router.post("/register", api::register_user);
    router.put("/login", api::login_user);

    // Private routes
    router.put("/logout", api::logout_user);

    router.post("/user/profile", api::get_user);
    router.put("/user/update", api::update_user);
    router.delete("/user/delete", api::delete_user);

    router.put("/user/horiz-cert", api::generate_horiz_cert);
    router.put("/user/vert-cert", api::generate_vert_cert);

    router.post("/admin/users", api::list_users);
    router.post("/admin/user", api::show_user);
    router.put("/admin/update", api::admin_update_user);
    router.put("/admin/horiz-cert", api::admin_generate_horiz_cert);
    router.put("/admin/horiz-cert", api::admin_generate_vert_cert);
    router.delete("/admin/delete", api::admin_delete_user);

    router.get("/pending-requests", api::list_pending_requests);
    router.delete("/pending-requests", api::delete_pending_request);

    router.handle(req)
}
