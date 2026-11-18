//! The names a function may not give a variable: its own, over the sets
//! every function of the binary shares.

use std::collections::HashSet;

/// A set of names that takes new ones.
pub(crate) trait Taken {
    /// Takes `name`; false when it was taken already.
    fn take(&mut self, name: String) -> bool;
}

impl Taken for HashSet<String> {
    fn take(&mut self, name: String) -> bool {
        self.insert(name)
    }
}

/// Names taken in one function, over sets shared by the whole binary.
///
/// A binary has as many function and data names as it has symbols, so
/// copying them into a set for each function costs more than the function.
#[derive(Clone, Default)]
pub(crate) struct Names<'shared> {
    shared: Vec<&'shared HashSet<String>>,
    own: HashSet<String>,
}

impl<'shared> Names<'shared> {
    /// `own` over each set of `shared`.
    pub(crate) fn over(
        shared: impl IntoIterator<Item = &'shared HashSet<String>>,
        own: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            shared: shared.into_iter().collect(),
            own: own.into_iter().collect(),
        }
    }

    pub(crate) fn contains(&self, name: &str) -> bool {
        self.own.contains(name) || self.shared.iter().any(|shared| shared.contains(name))
    }

    /// Takes `name`; false when it was taken already.
    pub(crate) fn insert(&mut self, name: String) -> bool {
        if self.shared.iter().any(|shared| shared.contains(&name)) {
            return false;
        }
        self.own.insert(name)
    }
}

impl Extend<String> for Names<'_> {
    fn extend<T: IntoIterator<Item = String>>(&mut self, names: T) {
        self.own.extend(names);
    }
}

impl Taken for Names<'_> {
    fn take(&mut self, name: String) -> bool {
        self.insert(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_behave_as_one_set_of_their_own_and_shared_names() {
        let first = HashSet::from(["main".to_owned(), "puts".to_owned()]);
        let second = HashSet::from(["table".to_owned()]);
        let mut names = Names::over([&first, &second], ["v1".to_owned()]);
        let mut plain: HashSet<String> = first
            .iter()
            .chain(&second)
            .cloned()
            .chain(["v1".to_owned()])
            .collect();
        for name in ["main", "table", "v1", "v2", "v2", "puts", "other"] {
            assert_eq!(names.contains(name), plain.contains(name), "{name}");
            assert_eq!(
                names.insert(name.to_owned()),
                plain.insert(name.to_owned()),
                "{name}"
            );
            assert!(names.contains(name));
        }
        names.extend(["main".to_owned(), "late".to_owned()]);
        assert!(names.contains("late"));
        assert!(!names.insert("late".to_owned()));
    }
}
