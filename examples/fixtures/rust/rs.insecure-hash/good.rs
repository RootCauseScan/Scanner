use md2::{Md2};
use md4::{Md4};
use md5::{Md5};
use sha1::{Sha1};
use sha2::{Sha256};

// ok: insecure-hashes
let mut hasher = Sha256::new();
