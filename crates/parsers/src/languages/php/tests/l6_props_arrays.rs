use crate::parse_php;
use ir::{DFNodeKind, FileIR};

#[test]
fn l6_prop_array_flow() {
    let code = r#"<?php
class C { public $f; }
$o = new C();
$o->f = $_GET['a'];
echo $o->f;
# $arr = [];
# $arr['k'] = $_GET['b'];
# echo $arr['k'];
"#;
    let mut fir = FileIR::new("test.php".into(), "php".into());
    parse_php(code, &mut fir).expect("parse php");
    let dfg = fir.dfg.expect("dfg");
    let obj_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "o.f" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .unwrap();
    let obj_use = dfg
        .nodes
        .iter()
        .find(|n| n.name == "o.f" && matches!(n.kind, DFNodeKind::Use))
        .map(|n| n.id)
        .unwrap();
    assert!(obj_def != obj_use);
}
