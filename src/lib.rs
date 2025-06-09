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

    router.get_async("/test", api::test);
    // Public routes
    router.post_async("/register", api::user_register);
    router.put("/login", api::user_login);

    // Private routes
    router.put("/logout", api::user_logout);

    router.post("/user/profile", api::user_profile);
    router.put("/user/update", api::user_update);
    router.delete("/user/delete", api::user_delete);

    router.put("/user/horiz-cert", api::generate_horiz_cert);
    router.put("/user/vert-cert", api::generate_vert_cert);

    router.post("/admin/users", api::list_users);
    router.post("/admin/user", api::show_user);
    router.put("/admin/update", api::admin_user_update);
    router.put("/admin/horiz-cert", api::admin_generate_horiz_cert);
    router.put("/admin/horiz-cert", api::admin_generate_vert_cert);
    router.delete("/admin/delete", api::admin_user_delete);

    router.handle(req)
}
