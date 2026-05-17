use assert_cmd::Command;

#[test]
fn rejects_invalid_input() {
    let mut cmd = Command::cargo_bin("bytecode_decompiler").unwrap();
    cmd.arg("tests/fixtures/invalid.bin");
    cmd.assert().failure();
}
