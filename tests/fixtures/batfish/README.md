# Batfish live-test fixture

`reference/` is the "before" snapshot. `candidate_r1.cfg` is a full replacement config
(config_import) that introduces three realistic mistakes:

1. `permit tcp … eq 22` above the guest→CDE deny, which opens SSH into the CDE
   (`guest-cannot-reach-cde` regresses from pass to fail);
2. `deny tcp any any eq 23` after `permit ip any any`, a shadowed line
   (`no-shadowed-acl-lines` regresses);
3. `ip access-group LAB_IN` with no such ACL, an undefined reference
   (`no-undefined-references` regresses).

`guest-can-reach-web` must stay a pass before and after. Used by
`tests/batfish_live_test.py`, which runs in the CI `batfish` job against `batfish/allinone`.
