# nix-darwin module for pymacdns: a macOS DNS forwarder that installs
# itself as the highest-priority resolver while it runs.
#
# Import by path from the working copy:
#
#   imports = [ /Users/lillecarl/Code/pymacdns/nix/darwin-module.nix ];
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.pymacdns;
  toml = pkgs.formats.toml { };
  configFile = toml.generate "pymacdns-config.toml" (
    {
      server =
        {
          listen = cfg.listen;
          timeout = cfg.timeout;
          interval = cfg.interval;
          route_filter = cfg.routeFilter;
          control_socket = cfg.controlSocket;
          system_dns = cfg.systemDns;
        }
        // lib.optionalAttrs (cfg.controlSocketGroup != null) {
          control_socket_group = cfg.controlSocketGroup;
        }
        // lib.optionalAttrs (cfg.resolvConf != null) {
          resolv_conf = cfg.resolvConf;
        };
    }
    // lib.optionalAttrs (cfg.resolvers != [ ]) { resolver = cfg.resolvers; }
  );
in
{
  options.services.pymacdns = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether to run pymacdns as a system daemon.";
    };

    package = lib.mkOption {
      type = lib.types.package;
      # The source tree's own default.nix, so the package builds against this
      # configuration's package set and no second nixpkgs is instantiated.
      default = (import ./.. { inherit pkgs; }).pymacdns;
      defaultText = lib.literalExpression "(import pymacdns-source { inherit pkgs; }).pymacdns";
      description = "The pymacdns package to run.";
    };

    listen = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "127.0.0.1:53"
        "[::1]:53"
      ];
      description = ''
        "host:port" pairs to listen on. Port 53 needs root, which the
        system daemon has.
      '';
    };

    timeout = lib.mkOption {
      type = lib.types.number;
      default = 2.0;
      description = "Seconds to wait for an upstream answer.";
    };

    interval = lib.mkOption {
      type = lib.types.number;
      default = 1.0;
      description = "Seconds between upstream and route refreshes.";
    };

    routeFilter = lib.mkOption {
      type = lib.types.enum [
        "off"
        "family"
        "prefix"
      ];
      default = "off";
      description = "Whether to prune unroutable addresses from responses.";
    };

    controlSocket = lib.mkOption {
      type = lib.types.str;
      default = "/var/run/pymacdns.sock";
      description = "Control socket for `pymacdns cache list|remove|clear`.";
    };

    controlSocketGroup = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "staff";
      description = ''
        Group allowed onto the control socket (chgrp + 0770 by the
        root daemon); null keeps owner-only 0600.
      '';
    };

    resolvConf = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/etc/resolv.conf";
      description = ''
        Point this resolv.conf at our listeners while running. The daemon
        inserts a delimited block and removes only that block on exit;
        null manages nothing. macOS regenerates /etc/resolv.conf on
        every DNS change, systemDns included, and drops the block; the
        daemon checks every 2s and puts it back.
      '';
    };

    systemDns = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Make our listeners the first resolver of macOS itself, for every
        name except the mDNS domains. The daemon publishes a temporary
        SCDynamicStore entry; configd removes it when the daemon exits,
        SIGKILL included. Needs every listen entry on one port.
      '';
    };

    resolvers = lib.mkOption {
      type = lib.types.listOf (
        lib.types.submodule {
          options = {
            domain = lib.mkOption {
              type = lib.types.str;
              default = "";
              description = "Domain to pin; empty routes everything.";
            };
            nameservers = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              description = "Upstream servers for the domain.";
            };
            priority = lib.mkOption {
              type = lib.types.int;
              default = 0;
              description = "Lower wins on ties; negatives beat discovery.";
            };
          };
        }
      );
      default = [ ];
      description = "Pinned resolvers, rendered as [[resolver]] entries.";
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [
        "--marker-file"
        "/var/run/pymacdns.installed"
      ];
      description = "Extra arguments appended to the daemon command line.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    environment.etc."pymacdns/config.toml".source = configFile;

    # A daemon released by `pymacdns nuke` keeps running, and launchd
    # reloads it only when the plist changes. Ask it to install again,
    # so every switch restores DNS; for an installed daemon it is a
    # no-op. Never fails the switch: a daemon that is still starting
    # installs on its own.
    system.activationScripts.postActivation.text = lib.mkAfter ''
      ${lib.getExe cfg.package} --config ${configFile} restore \
        || echo "pymacdns: restore skipped; the daemon installs when it starts" >&2
    '';

    launchd.daemons.pymacdns = {
      serviceConfig = {
        # ProgramArguments and not `command`: no shell quoting between the
        # option values and the daemon's argv. The values reach the
        # daemon as "$@".
        #
        # wait4path, because launchd loads this plist at boot before the
        # /nix volume is mounted: a bare store path fails to spawn with
        # exit 78 (EX_CONFIG) and the job then stays in "spawn scheduled"
        # until a manual kickstart. Measured on macOS 27 after a reboot.
        #
        # --config names the generated file by store path rather than
        # relying on the /etc default below: the path embeds the config
        # hash, so any option change alters the plist and launchd
        # restarts the daemon. Without it a config-only switch leaves
        # the old process (and its startup-time settings) running.
        ProgramArguments =
          [
            "/bin/sh"
            "-c"
            ''/bin/wait4path /nix/store && exec "$@"''
            "pymacdns"
            (lib.getExe cfg.package)
            "--config"
            "${configFile}"
          ]
          ++ cfg.extraArgs;
        # The store Python verifies TLS against this bundle: the
        # launchd environment carries no SSL_CERT_FILE of its own, and
        # without it every tls:// upstream fails closed at handshake.
        EnvironmentVariables.SSL_CERT_FILE =
          "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
        RunAtLoad = true;
        # The supervisor inside already reaps either side on SIGKILL; this
        # only restarts a daemon that exited on its own.
        KeepAlive = true;
        StandardOutPath = "/var/log/pymacdns.log";
        StandardErrorPath = "/var/log/pymacdns.log";
      };
    };
  };
}
