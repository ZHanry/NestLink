//! Literal Secret Service attributes follow the mature CLI option boundary.
//! Labels are fixed options at the callers; opaque bindings are never options.

pub(crate) fn lookup(binding: &str) -> [&str; 6] {
    [
        "lookup",
        "--",
        "application",
        "NestLink",
        "instance",
        binding,
    ]
}

pub(crate) fn store<'a>(label_option: &'a str, binding: &'a str) -> [&'a str; 7] {
    [
        "store",
        label_option,
        "--",
        "application",
        "NestLink",
        "instance",
        binding,
    ]
}
