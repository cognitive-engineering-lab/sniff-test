
struct TimeTravelingTaco {
  spice_level: int,
}

trait CosmicBeing {
  /// Turns object etheral and returns its sound effect
  fn become_etheral(&self) -> &str
}

impl CosmicBeing for TimeTravlingTaco {
  /// # Unsafe 
  /// * taco_spice_level : must be at least 3 spicy or it's definitely not ethereal
  fn become_etheral(&self) {
    if self.spice_level <= 3 {
      unsafe {
        // NOTE: uninteresting taco
        "AaaaAAAaahhhh *crash*"
        }
    } else {
      "zwoooOOOOP!"
    }
  }
}


#[hocklorp_attrs::check_unsafe]
fn main() {
  let x = 1;
}

