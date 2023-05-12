use biscuit::{Biscuit, error::{Token, Logic, FailedCheck}, 
  builder::BiscuitBuilder};
use time::{OffsetDateTime, format_description::well_known::Rfc3339,
  Duration};
#[cfg(feature = "tracing")]
use tracing::error;
use crate::error::MiddlewareError;

const TTL_CHECK: &'static str = "check if time($time), $time < ";

pub fn has_biscuit_expired(biscuit: &Biscuit) -> Result<bool, MiddlewareError> {
  let mut authorizer = biscuit.authorizer()?;
  let date = OffsetDateTime::now_utc()
    .format(&Rfc3339)
    .map_err(|_| {
      let trace = String::from("Date format error while checking if biscuit expired");
      #[cfg(feature = "tracing")]
      error!(trace);
      MiddlewareError::InternalServerError(trace)
    })?;

  authorizer.add_fact(format!("time({date})").as_str())?;

  let is_expired = authorizer.authorize()
    .or_else(|e| {
      if let Token::FailedLogic(logic) = e {
        return Err(logic)
      }

      Ok(0)
    }).or_else(|e| {
      if let Logic::NoMatchingPolicy{checks} = e {
        for check in &checks {
          if let FailedCheck::Block(block) = check {
            if block.rule.contains(TTL_CHECK) {
              return Ok::<usize, FailedCheck>(1)
            }
          }
        }
      }

      Ok(0)
    }).unwrap();

  Ok(if is_expired > 0 {true} else {false})
}

pub fn add_ttl_to_biscuit(
  biscuit: &mut BiscuitBuilder, 
  valid_duration: i64
) -> Result<(), MiddlewareError> {
  let valid_time = OffsetDateTime::now_utc() + Duration::seconds(valid_duration);
  
  biscuit.add_check(format!(
    "{TTL_CHECK}{}", 
    valid_time.format(&Rfc3339).map_err(|_| {
      let e = String::from("Date format error while checking if biscuit expired");

      MiddlewareError::InternalServerError(e)
    })?
  ).as_str())?;

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use biscuit::{KeyPair};
  use time::Duration;

  #[test]
  fn test_has_biscuit_expired() {
    // test expired and not biscuit
    let tests = vec![
      (OffsetDateTime::now_utc() + Duration::minutes(1), false),
      (OffsetDateTime::now_utc() - Duration::minutes(1), true)
    ];
    let root = KeyPair::new();

    for (time, expected) in tests { 
      let mut builder = Biscuit::builder();
      builder.add_check(format!(
        "{TTL_CHECK}{}", 
        time.format(&Rfc3339).unwrap()).as_str())
        .unwrap();
  
      let biscuit = builder.build(&root).unwrap();

      assert_eq!(has_biscuit_expired(&biscuit).unwrap(), expected);
    }

    // no check is not expired
    let biscuit = Biscuit::builder()
      .build(&root)
      .unwrap();

    assert_eq!(has_biscuit_expired(&biscuit).unwrap(), false);

    // a check that fail but is not ttl
    let time = OffsetDateTime::now_utc() + Duration::minutes(1);
    let mut builder = Biscuit::builder();
    builder.add_check(format!(
      "{TTL_CHECK}{}", 
      time.format(&Rfc3339).unwrap()).as_str())
      .unwrap();
    builder.add_check(format!(
      "check if foo($bar), $bar < 12").as_str())
      .unwrap();
    
    let biscuit = builder.build(&root).unwrap();

    assert_eq!(has_biscuit_expired(&biscuit).unwrap(), false);
  }
}