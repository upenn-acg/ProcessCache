use generator::{Scope, GeneratorImpl};
use actions::{Action, Actions};

/// Wrapper around our scope generator. Yields messages of type Actions
/// and receives an Action.
pub type Yielder = Scope<Action, Actions>;
pub type Coroutine<'a> = Box<GeneratorImpl<'a, Action, Actions>>;

macro_rules! make_handler {
    // Take a function fun and a list of N arguments to pass to the function.
    // Last argument of the function should be a Yielder.
    ($fun: ident, $($args: expr),*) => {
        Gn::new_scoped(move |mut y: Yielder| {
            $fun($($args),*, y);
            Action::Done.into()
        })
    };

    // No args case!
    ($fun: ident) => {
        Gn::new_scoped(move |mut y: Yielder| {
            $fun(y);
            Action::Done.into()
        })
    };
}
