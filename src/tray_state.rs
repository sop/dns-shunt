#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState {
    Unknown,
    Stopped,
    Running,
    Transitional,
    Missing,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MenuAvailability {
    pub start: bool,
    pub stop: bool,
    pub open_gui: bool,
    pub open_rules: bool,
}

impl ServiceState {
    pub fn menu_availability(self) -> MenuAvailability {
        MenuAvailability {
            start: self == Self::Stopped,
            stop: self == Self::Running,
            open_gui: self == Self::Running,
            open_rules: self == Self::Stopped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_actions_match_stopped_running_and_transitional_states() {
        assert_eq!(
            ServiceState::Stopped.menu_availability(),
            MenuAvailability {
                start: true,
                stop: false,
                open_gui: false,
                open_rules: true,
            }
        );
        assert_eq!(
            ServiceState::Running.menu_availability(),
            MenuAvailability {
                start: false,
                stop: true,
                open_gui: true,
                open_rules: false,
            }
        );
        for state in [
            ServiceState::Unknown,
            ServiceState::Transitional,
            ServiceState::Missing,
            ServiceState::Error,
        ] {
            assert_eq!(
                state.menu_availability(),
                MenuAvailability {
                    start: false,
                    stop: false,
                    open_gui: false,
                    open_rules: false,
                }
            );
        }
    }
}
