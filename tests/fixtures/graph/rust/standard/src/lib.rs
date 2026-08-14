// Standard-layout module tree: lib.rs -> foo.rs.  `crate::foo` is rooted at
// this file's `src` directory, not at the donor root.
pub mod foo;
use crate::foo as crate_foo;
