use crate::{Error, Result};

pub(crate) fn bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|_| Error::Rng)?;
    Ok(buf)
}
