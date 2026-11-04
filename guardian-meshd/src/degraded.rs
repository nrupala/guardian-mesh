// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

pub struct DegradedState {
    pub active: bool,
    pub trigger: String,
    pub safe_actions: Vec<String>,
    pub since_unix: u64,
}

impl DegradedState {
    pub fn inactive() -> Self {
        Self {
            active: false,
            trigger: String::new(),
            safe_actions: Vec::new(),
            since_unix: 0,
        }
    }

    pub fn active(trigger: String, safe_actions: Vec<String>, since_unix: u64) -> Self {
        Self {
            active: true,
            trigger,
            safe_actions,
            since_unix,
        }
    }

    pub fn allows(&self, action_type: &str) -> bool {
        if !self.active {
            return true;
        }
        self.safe_actions.iter().any(|a| a == action_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_allows_everything() {
        let state = DegradedState::inactive();
        assert!(state.allows("TOOL_CALL"));
        assert!(state.allows("CODE_EXECUTE"));
        assert!(state.allows(""));
    }

    #[test]
    fn active_with_empty_subset_allows_nothing() {
        let state = DegradedState::active("operator-declared".to_string(), Vec::new(), 1);
        assert!(!state.allows("TOOL_CALL"));
        assert!(!state.allows(""));
    }

    #[test]
    fn active_with_subset_allows_only_named_actions() {
        let state = DegradedState::active(
            "operator-declared".to_string(),
            vec!["SAFE_ACTION".to_string()],
            1,
        );
        assert!(state.allows("SAFE_ACTION"));
        assert!(!state.allows("TOOL_CALL"));
        assert!(!state.allows("safe_action"));
        assert!(!state.allows("SAFE_ACTION_"));
    }
}
