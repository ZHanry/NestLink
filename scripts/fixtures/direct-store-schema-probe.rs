//! Compiled in hosted Actions against the unchanged pinned schema-50 Store.
use nestlink_storage::{StorageError, Store};
use std::path::Path;

fn main() {
    assert_eq!(std::env::var("GITHUB_ACTIONS").unwrap_or_default(), "true");
    assert_eq!(std::env::var("RUNNER_ENVIRONMENT").unwrap_or_default(), "github-hosted");
    let arguments: Vec<_> = std::env::args().collect();
    assert_eq!(arguments.len(), 4);
    assert_eq!(nestlink_storage::SCHEMA_VERSION, 50);
    let result = match arguments[1].as_str() {
        "existing" => Store::open_existing(Path::new(&arguments[2]), &arguments[3]),
        "open" => Store::open(Path::new(&arguments[2]), &arguments[3]),
        _ => panic!("unknown probe entry"),
    };
    match result {
        Err(StorageError::Invalid("unsupported NestLink database version")) => {
            println!("OLD_SCHEMA50_STORE_REJECTED_NEW_SCHEMA");
        }
        Err(error) => panic!("wrong refusal before the real schema gate: {error}"),
        Ok(_) => panic!("old Store admitted a database containing direct ancestry"),
    }
}
