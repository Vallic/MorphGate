//! A cloud's machines as hosts, the way a source says: which address, who to log in as, how to
//! group them (docs/features/cloud-sources.md).

use crate::{InventoryHost, Machine, Reach, Via};

/// A source's choices.
#[derive(Clone, Debug, Default)]
pub struct Shape<'a> {
    /// Private addresses (through the source's jump host); else public ones.
    pub private: bool,
    /// Who to log in as where a machine doesn't say.
    pub user: Option<&'a str>,
    /// Group by this tag's value; else by region, project or resource group.
    pub group_tag: Option<&'a str>,
    /// Through the cloud (`aws-ssm`, `aws-eice`, `gcp-iap`) rather than an address.
    pub through: Option<&'a str>,
}

/// How `m` is reached through `kind`, where it's that cloud's machine.
fn via(kind: &str, m: &Machine) -> Option<Via> {
    match (kind, &m.reach) {
        (
            "aws-ssm" | "aws-eice",
            Reach::Aws {
                instance_id,
                region,
            },
        ) => Some(Via {
            kind: kind.to_owned(),
            instance: instance_id.clone(),
            place: region.clone(),
            project: None,
        }),
        (
            "gcp-iap",
            Reach::Gcp {
                project,
                zone,
                name,
            },
        ) => Some(Via {
            kind: kind.to_owned(),
            instance: name.clone(),
            place: zone.clone(),
            project: Some(project.clone()),
        }),
        _ => None,
    }
}

/// What a source's machines make.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shaped {
    pub hosts: Vec<InventoryHost>,
    /// Running machines without the address the source uses, by name.
    pub without_address: Vec<String>,
}

/// Who to log in as on `provider`'s machines when neither the machine nor the source says.
fn usual_user(provider: &str) -> &'static str {
    match provider {
        "azure" => "azureuser",
        "hetzner" | "digitalocean" => "root",
        _ => "ec2-user",
    }
}

/// The port a machine's `morphgate:port` tag (AWS) or `morphgate-port` tag or label names.
fn port_of(m: &Machine) -> u16 {
    ["morphgate:port", "morphgate-port"]
        .iter()
        .find_map(|k| m.tags.get(*k))
        .and_then(|p| p.trim().parse().ok())
        .filter(|p| *p > 0)
        .unwrap_or(22)
}

/// `machines` of `provider` (`aws`, `gcp`, `azure`) as hosts. A stopped machine comes without an
/// address when it has none (the vault keeps the last one); a running one without the address
/// the source uses is left out, and said.
pub fn hosts(provider: &str, machines: &[Machine], shape: &Shape) -> Shaped {
    let mut out = Shaped::default();
    for m in machines {
        let through = shape.through.and_then(|k| via(k, m));
        // Through the cloud, the instance's id or name: what its host key is kept under.
        let address = match &through {
            Some(v) => Some(v.instance.clone()),
            None if shape.private => m.private_address.clone(),
            None => m.public_address.clone(),
        };
        if address.is_none() && m.running {
            out.without_address.push(m.name.clone());
            continue;
        }
        let group = shape
            .group_tag
            .and_then(|t| m.tags.get(t))
            .filter(|g| !g.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| m.place.clone());
        out.hosts.push(InventoryHost {
            external_id: m.external_id.clone(),
            group,
            label: m.name.clone(),
            hostname: address.unwrap_or_default(),
            port: port_of(m),
            user: m
                .user
                .clone()
                .or_else(|| shape.user.map(str::to_owned))
                .unwrap_or_else(|| usual_user(provider).to_owned()),
            login_command: None,
            jump: None,
            jump_command: None,
            no_sftp: false,
            no_forwarding: false,
            state: (!m.running).then(|| m.state.clone()),
            key_name: m.key_name.clone(),
            via: through,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Reach;

    fn machine(name: &str, public: Option<&str>, private: Option<&str>, running: bool) -> Machine {
        Machine {
            external_id: format!("aws:eu-central-1/{name}"),
            name: name.into(),
            place: "eu-central-1".into(),
            public_address: public.map(str::to_owned),
            private_address: private.map(str::to_owned),
            user: None,
            key_name: Some("deploy".into()),
            running,
            state: if running { "running" } else { "stopped" }.into(),
            tags: [("team".to_owned(), "shop".to_owned())].into(),
            reach: Reach::Aws {
                instance_id: name.into(),
                region: "eu-central-1".into(),
            },
        }
    }

    #[test]
    fn public_addresses_and_who_to_log_in_as() {
        let mut tagged = machine("web-2", Some("ec2-2.example"), Some("10.0.0.2"), true);
        tagged.user = Some("ubuntu".into());
        tagged.tags.insert("morphgate:port".into(), "2222".into());
        let machines = [
            machine("web-1", Some("ec2-1.example"), Some("10.0.0.1"), true),
            tagged,
            // Running without a public address: left out, and said.
            machine("db", None, Some("10.0.0.3"), true),
            // Stopped: no address now, kept.
            machine("batch", None, Some("10.0.0.4"), false),
        ];
        let s = hosts("aws", &machines, &Shape::default());
        assert_eq!(s.without_address, ["db"]);
        assert_eq!(s.hosts.len(), 3);
        let h = &s.hosts[0];
        assert_eq!(
            (
                h.hostname.as_str(),
                h.port,
                h.user.as_str(),
                h.group.as_str()
            ),
            ("ec2-1.example", 22, "ec2-user", "eu-central-1")
        );
        assert_eq!(h.key_name.as_deref(), Some("deploy"));
        assert!(!h.no_sftp && h.state.is_none());
        assert_eq!(
            (s.hosts[1].user.as_str(), s.hosts[1].port),
            ("ubuntu", 2222)
        );
        assert_eq!(
            (s.hosts[2].hostname.as_str(), s.hosts[2].state.as_deref()),
            ("", Some("stopped"))
        );
    }

    #[test]
    fn through_session_manager_every_machine_is_its_instance() {
        let machines = [
            machine("i-0aaa", Some("ec2-1.example"), Some("10.0.0.1"), true),
            machine("i-0bbb", None, None, true),
        ];
        let s = hosts(
            "aws",
            &machines,
            &Shape {
                through: Some("aws-ssm"),
                ..Shape::default()
            },
        );
        assert!(s.without_address.is_empty());
        assert_eq!(s.hosts[1].hostname, "i-0bbb");
        assert_eq!(
            s.hosts[1].via,
            Some(Via {
                kind: "aws-ssm".into(),
                instance: "i-0bbb".into(),
                place: "eu-central-1".into(),
                project: None,
            })
        );
    }

    #[test]
    fn private_addresses_a_default_user_and_groups_by_tag() {
        let machines = [machine("db", None, Some("10.0.0.3"), true)];
        let s = hosts(
            "aws",
            &machines,
            &Shape {
                private: true,
                user: Some("admin"),
                group_tag: Some("team"),
                through: None,
            },
        );
        let h = &s.hosts[0];
        assert_eq!(
            (h.hostname.as_str(), h.user.as_str(), h.group.as_str()),
            ("10.0.0.3", "admin", "shop")
        );
    }
}
