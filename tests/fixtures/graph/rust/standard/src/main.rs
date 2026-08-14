// Bin+lib variant of the standard-layout tree: main.rs -> foo.rs.  Both root
// files share the declared `src` crate boundary for literal module resolution.
mod foo;
use crate::foo as crate_foo;
