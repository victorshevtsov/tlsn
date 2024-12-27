//! This module handles the abort of notarization.
//!
//! The prover deals with a TLS verifier that is only a notary.

use super::{state::Abort, Prover, ProverError};
use tracing::instrument;

impl Prover<Abort> {
    /// Finalizes the notarization.
    #[instrument(level = "debug", skip_all, err)]
    pub async fn finalize(self) -> Result<(), ProverError> {
        let Abort { mux_ctrl, mux_fut } = self.state;

        // Wait for the notary to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        Ok(())
    }
}
