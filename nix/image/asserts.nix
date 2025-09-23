{
  config,
  lib,
  ...
}: let
  rootUserDisallowedFields = [
    "password"
    "hashedPassword"
    "initialPassword"
    "initialHashedPassword"
    "hashedPasswordFile"
  ];
in {
  assertions = [
    {
      assertion = config.services.getty.autologinUser == null;
      message = "Auto-login must be disabled for zero operator access";
    }
  ] ++ map (field: {
    assertion = config.users.users.root.${field} == null;
    message = "Root user must not have a password";
  }) rootUserDisallowedFields;

  # Disable all console login services for zero operator access
  systemd.services."autovt@" = lib.mkForce {};
  systemd.services."getty@" = lib.mkForce {};
  systemd.services.getty-static = lib.mkForce {};
  systemd.services."serial-getty@" = lib.mkForce {};
}
