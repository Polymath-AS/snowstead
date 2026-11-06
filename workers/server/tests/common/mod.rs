use std::sync::Arc;

use object_store::memory::InMemory;
use snowstead_server::storage::Storage;

pub fn storage() -> Storage {
    Storage::from_stores(Arc::new(InMemory::new()), Arc::new(InMemory::new()))
}
