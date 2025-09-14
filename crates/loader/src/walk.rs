use std::collections::{HashSet, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tracing::debug;

pub fn visit<F, C>(path: &Path, excludes: &F, callback: &mut C) -> anyhow::Result<()>
where
    F: Fn(&Path) -> bool,
    C: FnMut(&Path) -> anyhow::Result<()>,
{
    let mut pending: VecDeque<PathBuf> = VecDeque::new();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    pending.push_back(path.to_path_buf());

    while let Some(current) = pending.pop_front() {
        if !visited.insert(current.clone()) {
            continue;
        }
        if excludes(&current) {
            debug!(path = %current.display(), "Path excluded");
            continue;
        }
        let metadata = match fs::symlink_metadata(&current) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                debug!(path = %current.display(), "Permission denied");
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            debug!(path = %current.display(), "Symlink skipped");
            continue;
        }
        if file_type.is_file() {
            debug!(path = %current.display(), "File discovered");
            callback(&current)?;
        } else if file_type.is_dir() {
            debug!(path = %current.display(), "Entering directory");
            let entries = match fs::read_dir(&current) {
                Ok(e) => e,
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    debug!(path = %current.display(), "Permission denied");
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            for entry_res in entries {
                let entry = match entry_res {
                    Ok(e) => e,
                    Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                        debug!(path = %current.display(), "Permission denied");
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };
                let path = entry.path();
                let metadata = match fs::symlink_metadata(&path) {
                    Ok(m) => m,
                    Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                        debug!(path = %path.display(), "Permission denied");
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };
                if metadata.file_type().is_symlink() {
                    debug!(path = %path.display(), "Symlink skipped");
                    continue;
                }
                pending.push_back(path);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::visit;
    use std::collections::BTreeSet;
    use std::fs::{self};
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    #[test]
    fn visits_nested_directories() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        fs::create_dir_all(base.join("a/b")).unwrap();
        fs::write(base.join("root.txt"), b"").unwrap();
        fs::write(base.join("a/file.txt"), b"").unwrap();
        fs::write(base.join("a/b/leaf.txt"), b"").unwrap();

        let mut seen = BTreeSet::new();
        let mut cb = |p: &Path| {
            seen.insert(p.strip_prefix(base).unwrap().to_path_buf());
            Ok(())
        };
        visit(base, &|_| false, &mut cb).unwrap();

        let expected: BTreeSet<PathBuf> = [
            PathBuf::from("root.txt"),
            PathBuf::from("a/file.txt"),
            PathBuf::from("a/b/leaf.txt"),
        ]
        .into_iter()
        .collect();

        assert_eq!(seen, expected);
    }

    #[cfg(unix)]
    #[test]
    fn terminates_on_symlink_loop() {
        use std::os::unix::fs as unix_fs;

        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        fs::create_dir_all(base.join("a")).unwrap();
        fs::write(base.join("root.txt"), b"").unwrap();
        fs::write(base.join("a/file.txt"), b"").unwrap();
        unix_fs::symlink(base, base.join("a/loop")).unwrap();

        let mut seen = BTreeSet::new();
        let mut cb = |p: &Path| {
            seen.insert(p.strip_prefix(base).unwrap().to_path_buf());
            Ok(())
        };
        visit(base, &|_| false, &mut cb).unwrap();

        let expected: BTreeSet<PathBuf> = [PathBuf::from("root.txt"), PathBuf::from("a/file.txt")]
            .into_iter()
            .collect();

        assert_eq!(seen, expected);
    }

    #[cfg(unix)]
    #[test]
    fn skips_permission_denied_paths() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        fs::create_dir_all(base.join("a/private")).unwrap();
        fs::write(base.join("root.txt"), b"").unwrap();
        fs::write(base.join("a/public.txt"), b"").unwrap();
        fs::write(base.join("a/private/secret.txt"), b"").unwrap();
        fs::set_permissions(base.join("a/private"), fs::Permissions::from_mode(0o000)).unwrap();

        let mut seen = BTreeSet::new();
        let mut cb = |p: &Path| {
            seen.insert(p.strip_prefix(base).unwrap().to_path_buf());
            Ok(())
        };
        visit(base, &|_| false, &mut cb).unwrap();
        fs::set_permissions(base.join("a/private"), fs::Permissions::from_mode(0o755)).unwrap();

        assert!(seen.contains(Path::new("root.txt")));
        assert!(seen.contains(Path::new("a/public.txt")));
    }
}
