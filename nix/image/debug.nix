{
  config,
  lib,
  pkgs,
  ...
}:
let
  debugWarning = builtins.trace ''

    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                   WARNING!                                   ║
    ║                                                                              ║
    ║                            DEBUG MODE ENABLED                                ║
    ║                                                                              ║
    ║  This TEE image will have OPERATOR ACCESS ENABLED with security risks:       ║
    ║  • Console login services are ENABLED                                        ║
    ║  • Auto-login as ROOT user is ENABLED                                        ║
    ║  • Security assertions are BYPASSED                                          ║
    ║                                                                              ║
    ║                         DO NOT USE IN PRODUCTION!                            ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝

  '' true;
in
assert debugWarning;
{
  services.getty.autologinUser = lib.mkOverride 10 "root";
  users.users.root.password = lib.mkOverride 10 "nixos";
  users.allowNoPasswordLogin = lib.mkOverride 10 false;
}
