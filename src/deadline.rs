use std::time::Instant;

use crate::error::{Error, Result};

pub(crate) fn passed(deadline: Option<Instant>) -> Result<()> {
    match deadline {
        Some(deadline) if Instant::now() > deadline => Err(Error::TimedOut),
        _ => Ok(()),
    }
}
