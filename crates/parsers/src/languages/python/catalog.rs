use std::collections::HashSet;

use crate::catalog::Catalog;

pub fn load_catalog() -> Catalog {
    Catalog {
        sources: HashSet::from([
            "input".into(),
            "sys.stdin.readline".into(),
            "request.args.get".into(),
            "request.args".into(),
            "request.form.get".into(),
            "request.form".into(),
            "request.values.get".into(),
            "request.values".into(),
            "flask.request.args.get".into(),
            "flask.request.form.get".into(),
            "flask.request.values.get".into(),
            "flask.request.args".into(),
            "flask.request.form".into(),
            "flask.request.values".into(),
        ]),
        sinks: HashSet::from([
            "os.execv".into(),
            "os.execve".into(),
            "os.execvp".into(),
            "os.execvpe".into(),
            "os.execl".into(),
            "os.execle".into(),
            "os.execlp".into(),
            "os.execlpe".into(),
            "subprocess.call".into(),
            "subprocess.run".into(),
            "subprocess.Popen".into(),
            "subprocess.check_call".into(),
            "subprocess.check_output".into(),
        ]),
        sanitizers: HashSet::from([
            "sanitize".into(),
            "clean".into(),
            "escape".into(),
            "html.escape".into(),
            "bleach.clean".into(),
        ]),
    }
}
