use assert_cmd::prelude::*;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use std::fs;
use std::process::Command;
use tempfile::{tempdir, TempDir};
use toml::Value as TomlValue;

#[test]
fn plugin_config_list() -> Result<(), Box<dyn std::error::Error>> {
    let home = TempDir::new()?;
    let plugin_dir = home.path().join(".config/rootcause/plugins/demo");
    fs::create_dir_all(&plugin_dir)?;
    fs::write(
        plugin_dir.join("plugin.toml"),
        "name='demo'\nversion='0.1.0'\napi_version='1.0.0'\nentry='noop'\ncapabilities=['analyze']\n",
    )?;
    fs::write(plugin_dir.join("noop"), "")?;
    Command::cargo_bin("rootcause")?
        .env("HOME", home.path())
        .args(["plugins", "config", "demo", "foo=1"])
        .assert()
        .success();
    Command::cargo_bin("rootcause")?
        .env("HOME", home.path())
        .args(["plugins", "list"])
        .assert()
        .success()
        .stdout(contains("foo (default: null, current: 1)"));
    Ok(())
}

#[test]
fn plugin_config_validates_schema() -> Result<(), Box<dyn std::error::Error>> {
    let home = TempDir::new()?;
    let plugin_dir = home.path().join(".config/rootcause/plugins/demo");
    fs::create_dir_all(&plugin_dir)?;
    fs::write(
        plugin_dir.join("plugin.toml"),
        "name='demo'\nversion='0.1.0'\napi_version='1.0.0'\nentry='noop'\ncapabilities=['analyze']\nconfig_schema='schema.json'\n",
    )?;
    fs::write(
        plugin_dir.join("schema.json"),
        r#"{"type":"object","properties":{"level":{"type":"string"}}}"#,
    )?;
    fs::write(plugin_dir.join("noop"), "")?;

    Command::cargo_bin("rootcause")?
        .env("HOME", home.path())
        .args(["plugins", "config", "demo", "level=high"])
        .assert()
        .success();

    Command::cargo_bin("rootcause")?
        .env("HOME", home.path())
        .args(["plugins", "config", "demo", "foo=1"])
        .assert()
        .failure()
        .stderr(contains("unknown option 'foo'"));

    Ok(())
}

#[test]
fn plugin_ping_times_out() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    fs::write(
        dir.path().join("plugin.toml"),
        "name='hang'\nversion='0.1.0'\napi_version='1.0.0'\nentry='sleep.sh'\ncapabilities=['analyze']\n",
    )?;
    let script = dir.path().join("sleep.sh");
    fs::write(&script, "#!/bin/sh\nsleep 10\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms)?;
    }

    Command::cargo_bin("rootcause")?
        .arg("plugins")
        .arg("ping")
        .arg(dir.path())
        .assert()
        .failure()
        .stderr(contains("plugin did not respond"));

    Ok(())
}

#[test]
fn enable_disable_updates_config() -> Result<(), Box<dyn std::error::Error>> {
    let home = TempDir::new()?;
    let plugin_name = "demo";

    Command::cargo_bin("rootcause")?
        .env("HOME", home.path())
        .args(["plugins", "disable", plugin_name])
        .assert()
        .success();

    let cfg_path = home.path().join(".config/rootcause/config.toml");
    let contents = fs::read_to_string(&cfg_path)?;
    assert!(contents.contains("enabled = false"));

    Command::cargo_bin("rootcause")?
        .env("HOME", home.path())
        .args(["plugins", "enable", plugin_name])
        .assert()
        .success();

    let contents = fs::read_to_string(cfg_path)?;
    assert!(contents.contains("enabled = true"));
    Ok(())
}

#[test]
fn remove_nonexistent_lists_installed() -> Result<(), Box<dyn std::error::Error>> {
    let home = TempDir::new()?;
    let plugin_dir = home.path().join(".config/rootcause/plugins/demo");
    fs::create_dir_all(&plugin_dir)?;
    fs::write(
        plugin_dir.join("plugin.toml"),
        "name='demo'\nversion='0.1.0'\napi_version='1.0.0'\nentry='noop'\ncapabilities=['analyze']\n",
    )?;
    fs::write(plugin_dir.join("noop"), "")?;

    Command::cargo_bin("rootcause")?
        .env("HOME", home.path())
        .args(["plugins", "remove", "missing"])
        .assert()
        .failure()
        .stdout(
            contains("Plugin 'missing' not found")
                .and(contains("Listing installed plugins"))
                .and(contains("demo")),
        );
    Ok(())
}

#[test]
fn remove_plugin_cleans_config() -> Result<(), Box<dyn std::error::Error>> {
    let home = TempDir::new()?;
    let plugin_dir = home.path().join(".config/rootcause/plugins/demo");
    fs::create_dir_all(&plugin_dir)?;
    fs::write(
        plugin_dir.join("plugin.toml"),
        "name='demo'\nversion='0.1.0'\napi_version='1.0.0'\nentry='noop'\ncapabilities=['analyze']\n",
    )?;
    fs::write(plugin_dir.join("noop"), "")?;

    Command::cargo_bin("rootcause")?
        .env("HOME", home.path())
        .args(["plugins", "config", "demo", "foo=1"])
        .assert()
        .success();

    let cfg_path = home.path().join(".config/rootcause/config.toml");
    let cfg_contents = fs::read_to_string(&cfg_path)?;
    assert!(cfg_contents.contains("foo"));

    Command::cargo_bin("rootcause")?
        .env("HOME", home.path())
        .args(["plugins", "remove", "demo"])
        .assert()
        .success();

    let cfg_contents = fs::read_to_string(&cfg_path)?;
    let cfg: TomlValue = toml::from_str(&cfg_contents)?;
    assert!(cfg.get("plugins").and_then(|p| p.get("demo")).is_none());
    Ok(())
}

const GOOD_PLUGIN: &str = r"#!/usr/bin/env python3
import json,sys
for line in sys.stdin:
    req=json.loads(line)
    i=req.get('id')
    m=req.get('method')
    if m=='plugin.init':
        resp={'jsonrpc':'2.0','id':i,'result':{'ok':True,'capabilities':['analyze'],'plugin_version':'1.0.0'}}
    elif m=='plugin.ping':
        resp={'jsonrpc':'2.0','id':i,'result':{'pong':True}}
    elif m=='file.analyze':
        resp={'jsonrpc':'2.0','id':i,'result':{'findings':[]}}
    elif m=='plugin.shutdown':
        resp=None
    else:
        resp={'jsonrpc':'2.0','id':i,'error':{'code':-32601,'message':'method not found'}}
    if resp is not None:
        print(json.dumps(resp))
        sys.stdout.flush()
    if m=='plugin.shutdown':
        break
";

const BAD_PLUGIN: &str = r"#!/usr/bin/env python3
import json,sys
for line in sys.stdin:
    req=json.loads(line)
    i=req.get('id')
    m=req.get('method')
    if m=='plugin.init':
        resp={'jsonrpc':'2.0','id':i,'result':{'ok':True,'capabilities':['analyze'],'plugin_version':'1.0.0'}}
    elif m=='plugin.ping':
        resp={'jsonrpc':'2.0','id':i,'result':{'pong':True}}
    elif m in ('file.analyze','file.transform'):
        resp={'jsonrpc':'2.0','id':i,'result':{}}
    elif m=='plugin.shutdown':
        resp=None
    else:
        resp={'jsonrpc':'2.0','id':i,'error':{'code':-32601,'message':'method not found'}}
    if resp is not None:
        print(json.dumps(resp))
        sys.stdout.flush()
    if m=='plugin.shutdown':
        break
";

#[test]
fn verify_plugin_checks_capabilities() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    fs::write(dir.path().join("plugin.toml"), "name='demo'\nversion='0.1.0'\napi_version='1.0.0'\nentry='python3 plugin.py'\ncapabilities=['analyze']\n")?;
    fs::write(dir.path().join("plugin.py"), GOOD_PLUGIN)?;
    Command::cargo_bin("rootcause")?
        .args(["plugins", "verify", dir.path().to_str().unwrap()])
        .assert()
        .success();

    let dir_bad = tempdir()?;
    fs::write(dir_bad.path().join("plugin.toml"), "name='demo'\nversion='0.1.0'\napi_version='1.0.0'\nentry='python3 plugin.py'\ncapabilities=['analyze']\n")?;
    fs::write(dir_bad.path().join("plugin.py"), BAD_PLUGIN)?;
    Command::cargo_bin("rootcause")?
        .args(["plugins", "verify", dir_bad.path().to_str().unwrap()])
        .assert()
        .failure();
    Ok(())
}
