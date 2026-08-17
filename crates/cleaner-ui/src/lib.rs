pub mod bridge;
pub mod view_models;

pub use bridge::setup_ui_bridge;
pub use view_models::AppWindow;

use slint::ComponentHandle;

/// Launches the Slint Desktop UI event loop.
pub fn run_ui() -> Result<(), slint::PlatformError> {
    let window = AppWindow::new()?;
    setup_ui_bridge(&window);
    window.run()
}
