#[macro_export]
/// Simple macro that adds the current function's name to a string. Meant to be used with
/// anyhow::with_context.
/// Instead of having to write:
///
/// We can just write:
///
/// Basically wraps the format!() macro adding prepending the function name to the string.
/// Functions exactly like format!().
macro_rules! context {
    ($str_literal:expr, $($arg:expr),*) => {
        format!(concat!("{}(): ", $str_literal, " file: {}, line: {}."),
                   crate::function_name!(), $($arg),*, std::file!(), std::line!())
    };
    ($str_literal:expr) => {
        format!(concat!("{}(): ", $str_literal, " file: {}, line: {}."),
                   crate::function_name!(), std::file!(), std::line!())
    };
}

#[macro_export]
/// Return function name.
/// If this is called from a closure so we omit everything else. So instead of:
/// io_tracker::execution::do_run_process::{{closure}}::{{closure}}:
/// we get:
///io_tracker::execution::do_run_process
macro_rules! function_name {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        match &name[..name.len()].find("::{{closure}}") {
            Some(pos) => &name[..*pos],
            None => &name[..name.len() - 3],
        }
    }};
}
