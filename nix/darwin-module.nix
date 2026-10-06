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
        network changes, which silently drops the block until restart --
        the failure direction is plain DHCP DNS, not an outage.
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

    launchd.daemons.pymacdns = {
      serviceConfig = {
        # ProgramArguments and not `command`: no shell quoting between the
        # option values and the daemon's argv.
        ProgramArguments = [ (lib.getExe cfg.package) ] ++ cfg.extraArgs;
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
