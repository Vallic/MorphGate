//! Royal TS (and Royal TSX) documents, `.rtsz` and the older `.rtsx`: XML with an element per
//! object (`RoyalFolder`, `RoyalSSHConnection`, `RoyalCredential`…) whose child elements are its
//! properties, as Royal's scripting reference names them (`URI`, `Port`, `CredentialMode`…).
//! SSH connections become hosts, the folders they're in their group, the credentials they use
//! their user and key. Passwords stay behind: the document keeps them encrypted.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;

use quick_xml::events::Event;

use super::{Loaded, Plan, Planned, PlannedAuth, local_user, split_address, text};
use crate::util::expand_home;

pub(super) fn load(name: String, bytes: &[u8]) -> Result<Loaded, String> {
    let xml = text(&unpack(bytes)?);
    if !xml.trim_start().starts_with('<') {
        return Err(format!(
            "{name} can't be read: it isn't a Royal TS document, or the whole document is encrypted (Royal TS can save it without that)"
        ));
    }
    let root = parse(&xml).map_err(|e| format!("{name} isn't a Royal TS document: {e}"))?;
    let document = Document::new(&root);
    let (hosts, listed, warnings) = document.plan(&local_user());
    Ok(Loaded {
        source: name,
        origin: "Royal TS",
        plan: Plan::ordered(hosts),
        listed,
        warnings,
        passphrases: HashMap::new(),
    })
}

/// The document's XML, from the file as saved: as it is, or compressed (gzip, zip).
fn unpack(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let bad = |e: std::io::Error| format!("the document can't be unpacked: {e}");
    match bytes {
        [0x1F, 0x8B, ..] => {
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(bytes)
                .read_to_end(&mut out)
                .map_err(bad)?;
            Ok(out)
        }
        [b'P', b'K', 3, 4, ..] => {
            let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
                .map_err(|e| format!("the document can't be unpacked: {e}"))?;
            let names: Vec<String> = zip.file_names().map(str::to_owned).collect();
            let entry = names
                .iter()
                .find(|n| n.to_lowercase().ends_with(".xml"))
                .or(names.first())
                .ok_or("the document is empty")?;
            let mut out = Vec::new();
            zip.by_name(entry)
                .map_err(|e| format!("the document can't be unpacked: {e}"))?
                .read_to_end(&mut out)
                .map_err(bad)?;
            Ok(out)
        }
        _ => Ok(bytes.to_vec()),
    }
}

/// An XML element: its name, text and child elements.
#[derive(Debug, Default)]
struct Node {
    name: String,
    text: String,
    children: Vec<Node>,
}

fn parse(xml: &str) -> Result<Node, String> {
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut stack = vec![Node::default()];
    let name = |n: &str| n.to_owned();
    loop {
        let event = reader.read_event().map_err(|e| e.to_string())?;
        if let Event::Start(e) = &event {
            stack.push(Node {
                name: name(e.local_name().as_ref()),
                ..Node::default()
            });
            continue;
        }
        if let Event::End(_) = event {
            let node = stack.pop().ok_or("unbalanced elements")?;
            stack
                .last_mut()
                .ok_or("unbalanced elements")?
                .children
                .push(node);
            continue;
        }
        let top = stack.last_mut().ok_or("unbalanced elements")?;
        match event {
            Event::Empty(e) => top.children.push(Node {
                name: name(e.local_name().as_ref()),
                ..Node::default()
            }),
            Event::Text(t) => top.text.push_str(&t.into_inner()),
            Event::CData(c) => top.text.push_str(&c.into_inner()),
            Event::GeneralRef(r) => {
                if let Ok(Some(c)) = r.resolve_char_ref() {
                    top.text.push(c);
                } else {
                    top.text.push_str(match r.into_inner().as_ref() {
                        "lt" => "<",
                        "gt" => ">",
                        "amp" => "&",
                        "apos" => "'",
                        "quot" => "\"",
                        _ => "",
                    });
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if stack.len() != 1 {
        return Err("unbalanced elements".into());
    }
    Ok(stack.pop().unwrap_or_default())
}

/// A Royal object: its type (`RoyalSSHConnection`), properties, and the object it's in.
struct Object {
    kind: String,
    props: HashMap<String, String>,
    parent: Option<usize>,
}

impl Object {
    fn get(&self, prop: &str) -> &str {
        self.props.get(prop).map_or("", |v| v.trim())
    }

    fn is(&self, prop: &str) -> bool {
        self.get(prop).eq_ignore_ascii_case("true")
    }
}

struct Document {
    objects: Vec<Object>,
    by_id: HashMap<String, usize>,
}

/// Who a connection signs in as, from its credentials.
#[derive(Default)]
struct Credential {
    user: Option<String>,
    key: Option<String>,
    password: bool,
}

impl Document {
    fn new(root: &Node) -> Document {
        let mut objects = Vec::new();
        collect(root, None, &mut objects);
        let by_id = objects
            .iter()
            .enumerate()
            .filter(|(_, o)| !o.get("ID").is_empty())
            .map(|(i, o)| (o.get("ID").to_lowercase(), i))
            .collect();
        Document { objects, by_id }
    }

    /// The object `i` is in: its `ParentID`, else the element around it.
    fn parent(&self, i: usize) -> Option<usize> {
        let o = &self.objects[i];
        match o.get("ParentID") {
            "" => o.parent,
            id => self.by_id.get(&id.to_lowercase()).copied().or(o.parent),
        }
    }

    /// The folders a connection is in, outermost first, as one group name (`Production / Web`).
    /// A document's own top folder for connections ("Connections") is left out.
    fn folder(&self, i: usize) -> Option<String> {
        let mut names = Vec::new();
        let mut at = self.parent(i);
        while let Some(p) = at {
            if names.len() > 32 {
                break;
            }
            let o = &self.objects[p];
            if o.kind != "RoyalFolder" {
                break;
            }
            names.insert(0, o.get("Name").to_owned());
            at = self.parent(p);
        }
        if names
            .first()
            .is_some_and(|n| n.eq_ignore_ascii_case("Connections"))
        {
            names.remove(0);
        }
        names.retain(|n| !n.is_empty());
        (!names.is_empty()).then(|| names.join(" / "))
    }

    fn credential_object(&self, id: &str, name: &str) -> Option<&Object> {
        let by_id = (!id.is_empty())
            .then(|| self.by_id.get(&id.to_lowercase()))
            .flatten()
            .map(|i| &self.objects[*i]);
        by_id.or_else(|| {
            (!name.is_empty())
                .then(|| {
                    self.objects.iter().find(|o| {
                        o.kind == "RoyalCredential" && o.get("Name").eq_ignore_ascii_case(name)
                    })
                })
                .flatten()
        })
    }

    /// `CredentialMode`: 0 none, 1 the folder's, 2 given here, 3 a credential by id, 4 by name.
    fn credential(&self, i: usize, depth: usize) -> Credential {
        let o = &self.objects[i];
        let mode = match o.get("CredentialMode") {
            "" if !o.get("CredentialUsername").is_empty() => "2",
            m => m,
        };
        let from = |c: &Object| Credential {
            user: Some(c.get("UserName").to_owned()).filter(|u| !u.is_empty()),
            key: Some(c.get("PrivateKeyPath").to_owned())
                .filter(|k| !k.is_empty() && c.get("PrivateKeyMode") != "1"),
            password: !c.get("Password").is_empty(),
        };
        match mode {
            "1" if depth < 32 => self
                .parent(i)
                .map(|p| self.credential(p, depth + 1))
                .unwrap_or_default(),
            "2" => Credential {
                user: Some(o.get("CredentialUsername").to_owned()).filter(|u| !u.is_empty()),
                key: Some(o.get("CredentialKeyFile").to_owned())
                    .filter(|k| !k.is_empty() && o.get("CredentialKeyMode") != "1"),
                password: !o.get("CredentialPassword").is_empty(),
            },
            "3" | "4" => self
                .credential_object(o.get("CredentialId"), o.get("CredentialName"))
                .map(from)
                .unwrap_or_default(),
            _ => Credential::default(),
        }
    }

    fn plan(&self, local_user: &str) -> (Vec<(String, Planned)>, Vec<String>, Vec<String>) {
        let mut hosts = Vec::new();
        let mut listed = Vec::new();
        let mut other: BTreeMap<String, usize> = BTreeMap::new();
        let mut passwords = 0;
        for (i, o) in self.objects.iter().enumerate() {
            if !o.kind.ends_with("Connection") || o.is("IsConnectionTemplate") {
                continue;
            }
            let connection_type = o.get("ConnectionType").to_lowercase();
            let ssh = match o.kind.as_str() {
                "RoyalSSHConnection" | "RoyalTerminalConnection" => {
                    connection_type.is_empty() || connection_type.starts_with("ssh")
                }
                _ => false,
            };
            if !ssh {
                // A terminal connection's type (`telnet;Telnet`), else the object's (`RDS`).
                let kind = match o.get("ConnectionType").split(';').next_back() {
                    Some(t) if !t.is_empty() => t.to_owned(),
                    _ => o
                        .kind
                        .trim_start_matches("Royal")
                        .trim_end_matches("Connection")
                        .to_owned(),
                };
                *other.entry(kind).or_default() += 1;
                continue;
            }
            let uri = o.get("URI");
            let uri = uri
                .strip_prefix("ssh://")
                .unwrap_or(uri)
                .trim_end_matches('/');
            if uri.is_empty() {
                continue;
            }
            let (user_in_uri, hostname, port_in_uri) = split_address(uri);
            let port = o
                .get("Port")
                .parse()
                .ok()
                .filter(|p| *p > 0)
                .or(port_in_uri)
                .unwrap_or(22);
            let credential = self.credential(i, 0);
            let user = credential
                .user
                .clone()
                .or(user_in_uri)
                .unwrap_or_else(|| local_user.to_owned());
            let key = Some(o.get("PrivateKeyPath").to_owned())
                .filter(|k| !k.is_empty())
                .or(credential.key);
            let auth = match key {
                Some(k) => PlannedAuth::Key(expand_home(&k)),
                None => {
                    if credential.password {
                        passwords += 1;
                    }
                    PlannedAuth::Password(None)
                }
            };
            let label = Some(o.get("Name").to_owned())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| hostname.clone());
            let mut host = Planned::new(label, hostname, port, user, auth);
            host.group = self.folder(i);
            host.notes = o.get("Description").to_owned();
            host.forward_agent = o.is("SSHAllowAgentForwarding");
            let proxy = [o.get("ProxyMode"), o.get("ProxyModePutty")]
                .into_iter()
                .any(|m| !m.is_empty() && m != "0");
            if proxy {
                host.unsupported.push(format!(
                    "a proxy ({}:{})",
                    o.get("ProxyServer"),
                    o.get("ProxyPort")
                ));
            }
            if !o.get("SSHDetachedCertificate").is_empty() {
                host.certificates
                    .push(expand_home(o.get("SSHDetachedCertificate")));
            }
            if o.is("SSHEnableX11Forwarding") {
                host.unsupported.push("X11 forwarding".into());
            }
            let id = match o.get("ID") {
                "" => format!("object {i}"),
                id => id.to_owned(),
            };
            listed.push(id.clone());
            hosts.push((id, host));
        }
        let mut warnings = Vec::new();
        if passwords > 0 {
            warnings.push(if passwords == 1 {
                "Passwords stay in Royal TS, which keeps them encrypted: 1 host asks for its password when it connects.".to_owned()
            } else {
                format!("Passwords stay in Royal TS, which keeps them encrypted: {passwords} hosts ask for theirs when they connect.")
            });
        }
        if !other.is_empty() {
            let kinds: Vec<String> = other.iter().map(|(k, n)| format!("{k} ({n})")).collect();
            warnings.push(format!("Not SSH, so not imported: {}.", kinds.join(", ")));
        }
        (hosts, listed, warnings)
    }
}

/// Royal objects in `node`: elements named `Royal…` that hold properties.
fn collect(node: &Node, parent: Option<usize>, out: &mut Vec<Object>) {
    for child in &node.children {
        let object = child.name.starts_with("Royal") && !child.children.is_empty();
        if !object {
            collect(child, parent, out);
            continue;
        }
        let props = child
            .children
            .iter()
            .filter(|p| p.children.is_empty())
            .map(|p| (p.name.clone(), p.text.clone()))
            .collect();
        out.push(Object {
            kind: child.name.clone(),
            props,
            parent,
        });
        let me = out.len() - 1;
        collect(child, Some(me), out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped as Royal's scripting reference names objects and properties.
    const DOC: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<RTSZDocument>
  <RoyalDocument><ID>d0c</ID><Name>Work</Name></RoyalDocument>
  <RoyalFolder><ID>f-conn</ID><ParentID>d0c</ParentID><Name>Connections</Name></RoyalFolder>
  <RoyalFolder>
    <ID>f-prod</ID><ParentID>f-conn</ParentID><Name>Production</Name>
    <CredentialMode>3</CredentialMode><CredentialId>C-1</CredentialId>
  </RoyalFolder>
  <RoyalCredential><ID>c-1</ID><Name>deploy</Name><UserName>deploy</UserName>
    <Password>FLBmVEbJ==</Password><PrivateKeyPath>~/.ssh/deploy</PrivateKeyPath></RoyalCredential>
  <RoyalSSHConnection>
    <ID>s-1</ID><ParentID>f-prod</ParentID><Name>Web &amp; API</Name><URI>web.example.com</URI>
    <Port>2222</Port><CredentialMode>1</CredentialMode>
    <SSHAllowAgentForwarding>True</SSHAllowAgentForwarding>
    <Description>Front end</Description>
  </RoyalSSHConnection>
  <RoyalSSHConnection>
    <ID>s-2</ID><ParentID>f-prod</ParentID><Name>DB</Name><URI>ssh://dba@db.internal</URI>
    <CredentialMode>2</CredentialMode><CredentialUsername>postgres</CredentialUsername>
    <CredentialPassword>UzXEW845==</CredentialPassword>
    <ProxyMode>3</ProxyMode><ProxyServer>proxy.example.com</ProxyServer><ProxyPort>1080</ProxyPort>
  </RoyalSSHConnection>
  <RoyalSSHConnection>
    <ID>s-3</ID><Name>Switch</Name><URI>10.0.0.2</URI><ConnectionType>telnet;Telnet</ConnectionType>
  </RoyalSSHConnection>
  <RoyalRDSConnection><ID>r-1</ID><Name>Windows box</Name><URI>win.example.com</URI></RoyalRDSConnection>
  <RoyalSSHConnection>
    <ID>t-1</ID><Name>Template</Name><URI>x</URI><IsConnectionTemplate>True</IsConnectionTemplate>
  </RoyalSSHConnection>
</RTSZDocument>
"#;

    fn hosts(loaded: &Loaded) -> HashMap<&str, &Planned> {
        loaded
            .listed
            .iter()
            .map(|id| (id.as_str(), &loaded.plan.hosts[id]))
            .collect()
    }

    #[test]
    fn ssh_connections_become_hosts() {
        let loaded = load("work.rtsz".into(), DOC.as_bytes()).unwrap();
        assert_eq!(loaded.listed, ["s-1", "s-2"]);
        let h = hosts(&loaded);

        // Credentials from the folder, which names a credential.
        let web = h["s-1"];
        assert_eq!(web.label, "Web & API");
        assert_eq!(
            (web.hostname.as_str(), web.port, web.user.as_str()),
            ("web.example.com", 2222, "deploy")
        );
        assert!(matches!(&web.auth, PlannedAuth::Key(p) if p.ends_with(".ssh/deploy")));
        assert_eq!(web.group.as_deref(), Some("Production"));
        assert!(web.forward_agent);
        assert_eq!(web.notes, "Front end");

        let db = h["s-2"];
        assert_eq!(
            (db.hostname.as_str(), db.port, db.user.as_str()),
            ("db.internal", 22, "postgres")
        );
        assert_eq!(
            db.auth,
            PlannedAuth::Password(None),
            "the password stays encrypted in Royal TS"
        );
        assert_eq!(db.unsupported, ["a proxy (proxy.example.com:1080)"]);

        assert_eq!(
            loaded.warnings,
            [
                "Passwords stay in Royal TS, which keeps them encrypted: 1 host asks for its password when it connects.",
                "Not SSH, so not imported: RDS (1), Telnet (1)."
            ]
        );
    }

    #[test]
    fn compressed_documents_and_nested_objects() {
        // Objects inside their folder's element, with no ParentID; gzip.
        let nested = "<Doc><RoyalFolder><Name>Lab</Name>\
            <RoyalSSHConnection><Name>pi</Name><URI>pi@raspberry:2200</URI></RoyalSSHConnection>\
            </RoyalFolder></Doc>";
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, nested.as_bytes()).unwrap();
        let loaded = load("lab.rtsz".into(), &gz.finish().unwrap()).unwrap();
        let pi = &loaded.plan.hosts[&loaded.listed[0]];
        assert_eq!(
            (pi.user.as_str(), pi.hostname.as_str(), pi.port),
            ("pi", "raspberry", 2200)
        );
        assert_eq!(pi.group.as_deref(), Some("Lab"));

        let refused = load("x.rtsz".into(), b"\x00\x01encrypted")
            .map(|_| ())
            .unwrap_err();
        assert!(refused.contains("encrypted"));
    }
}
