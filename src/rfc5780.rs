//! RFC 5780 (NAT behaviour discovery) address arithmetic.
//!
//! RFC 5780 §5 needs the server to answer from **four** transport addresses:
//! both public IPs times both ports, so the client can check `change-port`
//! (Test II), `change-ip` (Test III) and both at once (Test IV).
//!
//! The usual implementation binds one wildcard socket and recovers the
//! destination address per datagram with `IP_PKTINFO` / `IPV6_RECVPKTINFO`,
//! which is platform-specific. This server instead binds **one socket per
//! address**: the destination of a datagram on a given socket is simply that
//! socket's own local address, so `local_addr()` answers "where did this
//! arrive?" and picking the answering socket answers "where does the reply
//! leave from?" — portable, and the four-way map below is pure arithmetic.
//!
//! The cost is that a wildcard (`0.0.0.0` / `[::]`) listen address cannot be
//! used here: with one socket per address there is no second address to switch
//! to. [`Plan::from_cli`] refuses that instead of silently degrading to a
//! plain RFC 5389 server, because a client that gets no `OTHER-ADDRESS` will
//! conclude "no NAT behaviour discovery here" and cannot tell why.

use std::net::{IpAddr, SocketAddr};

use crate::protocol::ChangeRequest;

/// Which two IPs / two ports this server answers on.
///
/// The four sockets are always `ip1:port1`, `ip1:port2`, `ip2:port1`, `ip2:port2`;
/// only `ip1:port1` is the address clients are expected to start from (the one
/// advertised in DNS / peer discovery).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    /// `ip1:port1`: the address the client probes first.
    pub primary: SocketAddr,
    /// `ip2`: the "other address" from `OTHER-ADDRESS` (RFC 5780 §7.4).
    pub other_ip: IpAddr,
    /// `port2`: the "other port" from `OTHER-ADDRESS`.
    pub other_port: u16,
}

impl Plan {
    /// Build a plan from an already-validated pair.
    ///
    /// Prefer [`Plan::from_cli`], which also rejects the cases that cannot be
    /// served (wildcards, identical IPs/ports).
    pub const fn new(primary: SocketAddr, other_ip: IpAddr, other_port: u16) -> Self {
        Self {
            primary,
            other_ip,
            other_port,
        }
    }

    /// Validate the `--listen` / `--alt-listen` / `--alt-port` triple.
    ///
    /// # Errors
    ///
    /// Returns an operator-facing message (the caller logs it and exits) when
    /// RFC 5780 cannot be served with the given addresses: a wildcard listen
    /// address, a wildcard or missing second IP, the same IP twice, two
    /// identical ports, a port of 0, or a port with no `+1` neighbour when
    /// `--alt-port` is omitted.
    pub fn from_cli(
        primary: SocketAddr,
        other: SocketAddr,
        other_port: Option<u16>,
    ) -> Result<Self, String> {
        if primary.ip().is_unspecified() {
            return Err(format!(
                "--alt-listen needs a concrete --listen address, got {primary}: RFC 5780 binds one \
                 socket per public IP, so a wildcard leaves nothing to change IP to (write e.g. \
                 --listen 203.0.113.5:3478 --alt-listen 203.0.113.50:3478)"
            ));
        }
        if primary.port() == 0 {
            return Err(format!(
                "--alt-listen needs a concrete port, got {primary}: --alt-port and RESPONSE-ORIGIN \
                 are meaningless when the kernel picks the port"
            ));
        }
        if primary.is_ipv4() != other.is_ipv4() {
            return Err(format!(
                "--alt-listen {other} must be the same IP family as --listen {primary}"
            ));
        }
        if other.ip().is_unspecified() {
            return Err(format!(
                "--alt-listen {other} must be a concrete public IP, not a wildcard"
            ));
        }
        if other.ip() == primary.ip() {
            return Err(format!(
                "--alt-listen {} must be a second IP: --listen {primary} already uses it, so \
                 CHANGE-REQUEST would have nothing to switch to",
                other.ip()
            ));
        }

        let other_port = match other_port {
            Some(port) => port,
            None => primary.port().checked_add(1).ok_or_else(|| {
                format!(
                    "--listen port {} has no +1 neighbour; pass --alt-port explicitly",
                    primary.port()
                )
            })?,
        };
        if other_port == 0 {
            return Err("--alt-port 0 is not a usable port".to_string());
        }
        if other_port == primary.port() {
            return Err(format!(
                "--alt-port {other_port} must differ from the --listen port: CHANGE-REQUEST needs \
                 a second port"
            ));
        }

        Ok(Self::new(primary, other.ip(), other_port))
    }

    /// Is `address` one of the four sockets this plan owns?
    ///
    /// Only these sockets take part in RFC 5780: they carry `RESPONSE-ORIGIN` /
    /// `OTHER-ADDRESS` and honour `CHANGE-REQUEST`. Every other listen address
    /// (extra `--listen` entries, all `--listen-v6`) is plain RFC 5389, so the
    /// caller needs this predicate rather than "is a plan configured?" — see
    /// `ServerContext::addresses` and the CHANGE-REQUEST branch in `decide`.
    pub fn is_plan_socket(&self, address: SocketAddr) -> bool {
        self.sockets().contains(&address)
    }

    /// The four addresses to bind UDP sockets on.
    pub fn sockets(&self) -> [SocketAddr; 4] {
        [
            self.primary,
            SocketAddr::new(self.other_ip, self.primary.port()),
            SocketAddr::new(self.primary.ip(), self.other_port),
            SocketAddr::new(self.other_ip, self.other_port),
        ]
    }

    /// The addresses to bind TCP listeners on (with `--tcp`).
    ///
    /// RFC 5780 only defines behaviour discovery over UDP, so TCP keeps the two
    /// IPs on the *primary* port: enough for a client that only wants to learn
    /// its mapped address over TCP, without a second pair of listeners whose
    /// `CHANGE-REQUEST` we would have to ignore anyway.
    pub fn tcp_listeners(&self) -> [SocketAddr; 2] {
        [
            self.primary,
            SocketAddr::new(self.other_ip, self.primary.port()),
        ]
    }

    /// Where the client should probe *instead of* `local`: the other IP and the
    /// other port.
    ///
    /// Symmetric (`other_of(other_of(local)) == local` for all four addresses),
    /// so a request that entered on the "other" address still gets a usable pair
    /// back instead of the useless "other address == the one you just used".
    pub fn other_of(&self, local: SocketAddr) -> SocketAddr {
        self.flipped(
            local,
            ChangeRequest {
                change_ip: true,
                change_port: true,
            },
        )
    }

    /// The address the response to a `CHANGE-REQUEST` arriving on `local` must
    /// leave from (RFC 5780 §7.2: `change-ip` flips only the IP, `change-port`
    /// only the port, both flips to the diagonal socket).
    pub fn changed(&self, local: SocketAddr, request: ChangeRequest) -> SocketAddr {
        self.flipped(local, request)
    }

    /// Flip the axes `request` asks for.
    ///
    /// Any address outside the four-socket set is treated as the primary on that
    /// axis; it cannot happen through [`Plan::sockets`], and answering from the
    /// primary is the only defined fallback.
    fn flipped(&self, local: SocketAddr, request: ChangeRequest) -> SocketAddr {
        let ip = if !request.change_ip {
            local.ip()
        } else if local.ip() == self.primary.ip() {
            self.other_ip
        } else {
            self.primary.ip()
        };
        let port = if !request.change_port {
            local.port()
        } else if local.port() == self.primary.port() {
            self.other_port
        } else {
            self.primary.port()
        };
        SocketAddr::new(ip, port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ip1:3478` primary, `ip2` other IP, `3479` other port — the deployment
    /// shape from the README.
    fn plan() -> Plan {
        Plan::new(
            "203.0.113.5:3478".parse().unwrap(),
            "203.0.113.50".parse().unwrap(),
            3479,
        )
    }

    fn addrs(list: &[SocketAddr]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn the_four_sockets_are_the_two_ips_on_the_two_ports() {
        assert_eq!(
            addrs(&plan().sockets()),
            vec![
                "203.0.113.5:3478",
                "203.0.113.50:3478",
                "203.0.113.5:3479",
                "203.0.113.50:3479",
            ]
        );
        // ...and TCP only takes the primary port on both IPs.
        assert_eq!(
            addrs(&plan().tcp_listeners()),
            vec!["203.0.113.5:3478", "203.0.113.50:3478"]
        );
    }

    #[test]
    fn only_the_four_sockets_are_plan_sockets() {
        let plan = plan();
        for address in plan.sockets() {
            assert!(plan.is_plan_socket(address), "{address}");
        }
        // 多地址 / v6 的普通 socket 都不在计划里：它们不能带 5780 属性、
        // 也不能被 CHANGE-REQUEST 换走。
        for address in [
            "203.0.113.5:3480",
            "203.0.113.6:3478",
            "[::1]:3478",
            "0.0.0.0:3478",
        ] {
            let address: SocketAddr = address.parse().unwrap();
            assert!(!plan.is_plan_socket(address), "{address}");
        }
    }

    #[test]
    fn other_of_swaps_both_axes_from_any_of_the_four_sockets() {
        let plan = plan();
        let expected = [
            ("203.0.113.5:3478", "203.0.113.50:3479"),
            ("203.0.113.50:3478", "203.0.113.5:3479"),
            ("203.0.113.5:3479", "203.0.113.50:3478"),
            ("203.0.113.50:3479", "203.0.113.5:3478"),
        ];
        for (local, other) in expected {
            let local: SocketAddr = local.parse().unwrap();
            let other: SocketAddr = other.parse().unwrap();
            assert_eq!(plan.other_of(local), other, "other_of({local})");
            // Symmetric: asking from the other socket comes back to the first.
            assert_eq!(plan.other_of(other), local, "other_of({other})");
        }
    }

    #[test]
    fn change_request_flips_exactly_the_requested_axes() {
        let plan = plan();
        let primary: SocketAddr = "203.0.113.5:3478".parse().unwrap();
        let cases = [
            (
                ChangeRequest {
                    change_ip: false,
                    change_port: false,
                },
                "203.0.113.5:3478",
            ),
            (
                ChangeRequest {
                    change_ip: false,
                    change_port: true,
                },
                "203.0.113.5:3479",
            ),
            (
                ChangeRequest {
                    change_ip: true,
                    change_port: false,
                },
                "203.0.113.50:3478",
            ),
            (
                ChangeRequest {
                    change_ip: true,
                    change_port: true,
                },
                "203.0.113.50:3479",
            ),
        ];
        for (request, expected) in cases {
            assert_eq!(
                plan.changed(primary, request),
                expected.parse::<SocketAddr>().unwrap(),
                "{request:?}"
            );
        }

        // The same request arriving on the diagonal socket comes back to primary.
        assert_eq!(
            plan.changed(
                "203.0.113.50:3479".parse().unwrap(),
                ChangeRequest {
                    change_ip: true,
                    change_port: true,
                }
            ),
            primary
        );
        // A single-axis request from a non-primary socket keeps the other axis.
        assert_eq!(
            plan.changed(
                "203.0.113.50:3478".parse().unwrap(),
                ChangeRequest {
                    change_ip: false,
                    change_port: true,
                }
            ),
            "203.0.113.50:3479".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn ipv6_needs_the_same_family_and_two_distinct_addresses() {
        let plan = Plan::from_cli(
            "[240b:4000::1]:3478".parse().unwrap(),
            "[240b:4000::2]:3478".parse().unwrap(),
            None,
        )
        .expect("v6 pair is valid");
        assert_eq!(
            addrs(&plan.sockets()),
            vec![
                "[240b:4000::1]:3478",
                "[240b:4000::2]:3478",
                "[240b:4000::1]:3479",
                "[240b:4000::2]:3479",
            ]
        );

        let mixed = Plan::from_cli(
            "203.0.113.5:3478".parse().unwrap(),
            "[240b:4000::2]:3478".parse().unwrap(),
            None,
        );
        assert!(mixed.is_err(), "mixed families must be refused");
    }

    #[test]
    fn cli_validation_refuses_what_rfc5780_cannot_serve() {
        let other = "203.0.113.50:3478".parse().unwrap();

        // Wildcard v4: the whole point of one-socket-per-address.
        let error = Plan::from_cli("0.0.0.0:3478".parse().unwrap(), other, None).unwrap_err();
        assert!(error.contains("concrete --listen"), "{error}");
        // Wildcard v6 too.
        let error = Plan::from_cli(
            "[::]:3478".parse().unwrap(),
            "[::1]:3478".parse().unwrap(),
            None,
        )
        .unwrap_err();
        assert!(error.contains("concrete --listen"), "{error}");
        // Port 0: RESPONSE-ORIGIN would be a lie.
        let error = Plan::from_cli("203.0.113.5:0".parse().unwrap(), other, None).unwrap_err();
        assert!(error.contains("concrete port"), "{error}");
        // Wildcard second IP.
        let error = Plan::from_cli(
            "203.0.113.5:3478".parse().unwrap(),
            "0.0.0.0:3478".parse().unwrap(),
            None,
        )
        .unwrap_err();
        assert!(error.contains("concrete public IP"), "{error}");
        // The same IP twice: CHANGE-REQUEST would be a no-op.
        let error = Plan::from_cli(
            "203.0.113.5:3478".parse().unwrap(),
            "203.0.113.5:3478".parse().unwrap(),
            None,
        )
        .unwrap_err();
        assert!(error.contains("second IP"), "{error}");
        // The same port twice.
        let error =
            Plan::from_cli("203.0.113.5:3478".parse().unwrap(), other, Some(3478)).unwrap_err();
        assert!(error.contains("--alt-port"), "{error}");
        // Port 0 as the alt port.
        assert!(
            Plan::from_cli("203.0.113.5:3478".parse().unwrap(), other, Some(0)).is_err(),
            "alt port 0 must be refused"
        );
        // No +1 neighbour for the default alt port.
        let error = Plan::from_cli("203.0.113.5:65535".parse().unwrap(), other, None).unwrap_err();
        assert!(error.contains("--alt-port"), "{error}");
    }

    #[test]
    fn default_alt_port_is_the_listen_port_plus_one() {
        let plan = Plan::from_cli(
            "203.0.113.5:3478".parse().unwrap(),
            "203.0.113.50:3478".parse().unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(plan.other_port, 3479);
        assert_eq!(plan.primary.port(), 3478);
        // The port inside --alt-listen is deliberately not used (see the CLI help).
        let plan = Plan::from_cli(
            "203.0.113.5:3478".parse().unwrap(),
            "203.0.113.50:40000".parse().unwrap(),
            Some(40100),
        )
        .unwrap();
        assert_eq!(plan.other_port, 40100);
    }
}
