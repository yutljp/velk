use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use crate::ir::{CType, Expr};
use crate::render::int::Printed;
use crate::render::naming::Place;

/// What printing an expression gave, kept while a body is rendered.
///
/// Naming the place an address points at prints the address, and printing a
/// load names its place, so without this the work doubles with every pointer
/// an expression follows. Nothing changes the context while a body is
/// rendered, so an expression prints the same each time.
#[derive(Default)]
pub(crate) struct Memo {
    kept: Cell<bool>,
    printed: RefCell<HashMap<(Expr, u32, u8), Printed>>,
    targets: RefCell<HashMap<Expr, Option<CType>>>,
    places: RefCell<HashMap<(Expr, u8), Option<Place>>>,
}

/// Keeps results in a [`Memo`] until dropped. It borrows the context, so
/// the context cannot change while results are kept.
pub(in crate::render) struct Kept<'m>(&'m Memo);

impl Memo {
    pub(in crate::render) fn keep(&self) -> Kept<'_> {
        self.kept.set(true);
        Kept(self)
    }

    pub(in crate::render) fn printed(
        &self,
        expr: &Expr,
        bits: u32,
        usage: u8,
        compute: impl FnOnce() -> Printed,
    ) -> Printed {
        if !self.kept.get() {
            return compute();
        }
        let key = (expr.clone(), bits, usage);
        if let Some(printed) = self.printed.borrow().get(&key) {
            return printed.clone();
        }
        let printed = compute();
        self.printed.borrow_mut().insert(key, printed.clone());
        printed
    }

    pub(in crate::render) fn target(
        &self,
        expr: &Expr,
        compute: impl FnOnce() -> Option<CType>,
    ) -> Option<CType> {
        if !self.kept.get() {
            return compute();
        }
        if let Some(target) = self.targets.borrow().get(expr) {
            return target.clone();
        }
        let target = compute();
        self.targets
            .borrow_mut()
            .insert(expr.clone(), target.clone());
        target
    }

    pub(in crate::render) fn place(
        &self,
        addr: &Expr,
        width: u8,
        compute: impl FnOnce() -> Option<Place>,
    ) -> Option<Place> {
        if !self.kept.get() {
            return compute();
        }
        let key = (addr.clone(), width);
        if let Some(place) = self.places.borrow().get(&key) {
            return place.clone();
        }
        let place = compute();
        self.places.borrow_mut().insert(key, place.clone());
        place
    }
}

impl Drop for Kept<'_> {
    fn drop(&mut self) {
        self.0.kept.set(false);
        self.0.printed.borrow_mut().clear();
        self.0.targets.borrow_mut().clear();
        self.0.places.borrow_mut().clear();
    }
}
