pub mod chaining;
pub mod command;
pub mod response;

pub use chaining::ChainingState;
pub use command::{Command, CommandError};
pub use response::{Reply, Status};

/// Application trait for APDU dispatch.
///
/// Each smart card application (e.g. FIDO, OpenPGP, PIV) implements this trait
/// to be selected by AID and to process APDU commands.
pub trait Application {
    /// The application identifier (AID) used for SELECT.
    fn aid(&self) -> &[u8];

    /// Called when the application is selected via a SELECT APDU.
    fn select(&mut self) -> Result<(), Status>;

    /// Called when the application is deselected (another application selected, or card reset).
    fn deselect(&mut self);

    /// Process an incoming APDU command and populate the reply buffer.
    fn call(&mut self, command: &Command, reply: &mut Reply) -> Result<(), Status>;
}
