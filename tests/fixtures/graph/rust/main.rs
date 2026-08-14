// UTF-8 provenance: café 😀. Module tree: main.rs:4 -> lib/mod.rs, then
// lib/mod.rs:3 -> lib/foo.rs. Use lines 6 and 7 follow that tree; line 8 is
// stdlib; line 9 is a valid glob from lib; line 10 aliases the foo child.
mod lib;

use crate::lib::foo::foo;
use crate::lib::foo as bar;
use std::fmt::Debug;
use crate::lib::*;
use crate::lib::{foo as foo_module};

struct Widget;
trait Render {}
struct Wrapper<T>(T);

impl Render for Widget {
    fn run(&self) {
        let note = "café 😀";
        foo();
        let _module_item = bar::foo;
        self.run();
        vec![note];
        bar::foo();
        let _debug: Option<&dyn Debug> = None;
        let _also_a_module = foo_module::foo;
    }
}

// This valid generic impl remains intentionally outside the v1 trait selector.
impl<T: Render> Render for Wrapper<T> {}
