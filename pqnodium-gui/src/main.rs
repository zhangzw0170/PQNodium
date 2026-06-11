use anyhow::Result;

slint::include_modules!();

fn main() -> Result<()> {
    let app = App::new()?;
    app.set_status_text("Starting...".into());
    app.run()?;
    Ok(())
}
