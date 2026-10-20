//! Snippets from a CSV file: a first line naming the columns (`Name`, `Command`, `Tags`, in any
//! order), then a snippet a line. A command of several lines is quoted, as spreadsheets write
//! it; so is a value with the separator in it. The page shows what's in the file and saves the
//! ones picked.

use serde::Serialize;
use tauri::AppHandle;

use crate::host_import::csv;

/// Header names (lowercase, letters and digits only) for each value.
const NAME: &[&str] = &["name", "label", "title", "snippetname"];
const COMMAND: &[&str] = &[
    "command", "commands", "body", "script", "content", "snippet", "cmd",
];
const TAGS: &[&str] = &["tags", "tag", "labels"];

/// A name made from a command lacking one: its first line, this long at most.
const NAME_CHARS: usize = 40;

/// The file "Download an example" saves: every case a real file has (a command with a comma, one
/// with quotes, one of several lines, a row without tags).
pub const EXAMPLE: &str = "Name,Command,Tags\r
Disk usage,df -h,\"linux,disk\"\r
Follow the system log,journalctl -f -n 100,linux\r
Restart nginx,sudo systemctl restart nginx && systemctl status nginx --no-pager,\"nginx,web\"\r
Database size,\"psql -c \"\"SELECT pg_size_pretty(pg_database_size(current_database()));\"\"\",postgres\r
Deploy,\"cd /srv/app\r
git pull --ff-only\r
./deploy.sh\",\r
";

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CsvSnippet {
    pub name: String,
    pub body: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnippetCsv {
    pub snippets: Vec<CsvSnippet>,
    /// Lines left out, and why.
    pub warnings: Vec<String>,
}

/// The snippets in a CSV file's text (`name` is the file's, for messages).
#[tauri::command]
pub fn snippets_read_csv(name: String, text: String) -> Result<SnippetCsv, String> {
    read(&name, &text)
}

/// Saves [`EXAMPLE`] in the downloads folder; says where.
#[tauri::command]
pub fn snippets_csv_example(app: AppHandle) -> Result<String, String> {
    let path = crate::util::download_path(&app, "morphgate-snippets-example", "csv")?;
    std::fs::write(&path, EXAMPLE).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(crate::util::saved(&path))
}

pub(crate) fn read(name: &str, text: &str) -> Result<SnippetCsv, String> {
    let rows = csv::parse(text);
    let Some((header, rows)) = rows.split_first() else {
        return Err(format!("{name} is empty"));
    };
    let header = csv::names(header);
    let column = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| header.iter().position(|h| h == n))
    };
    let Some(command) = column(COMMAND) else {
        return Err(format!(
            "{name} has no Command column: its first line names the columns (Name, Command, Tags)"
        ));
    };
    let (label, tags) = (column(NAME), column(TAGS));
    let at = |row: &[String], i: Option<usize>| {
        i.and_then(|i| row.get(i))
            .map(|v| v.trim().to_owned())
            .unwrap_or_default()
    };

    let mut snippets = Vec::new();
    let mut empty = Vec::new();
    // Line numbers as a spreadsheet shows them: the header is line 1.
    for (n, row) in rows.iter().enumerate() {
        // Lines end in \n, as a terminal takes them (a Windows file's \r\n would send two).
        let body = row
            .get(command)
            .map(|v| v.replace("\r\n", "\n").replace('\r', "\n"))
            .unwrap_or_default();
        let body = body.trim_end().trim_start_matches('\n');
        if body.trim().is_empty() {
            empty.push((n + 2).to_string());
            continue;
        }
        let name = match at(row, label) {
            name if !name.is_empty() => name,
            _ => short(body.lines().next().unwrap_or(body).trim()),
        };
        let tags = at(row, tags)
            .split([',', ';'])
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
            .collect();
        snippets.push(CsvSnippet {
            name,
            body: body.to_owned(),
            tags,
        });
    }
    let mut warnings = Vec::new();
    match empty.len() {
        0 => {}
        1 => warnings.push(format!(
            "Line {} has no command, so it's left out.",
            empty[0]
        )),
        _ => warnings.push(format!(
            "Lines {} have no command, so they're left out.",
            list(&empty)
        )),
    }
    Ok(SnippetCsv { snippets, warnings })
}

fn short(line: &str) -> String {
    match line.char_indices().nth(NAME_CHARS) {
        Some((at, _)) => format!("{}…", line[..at].trim_end()),
        None => line.to_owned(),
    }
}

/// "2, 5 and 9"; past five, "2, 5, 9, 11, 12 and 3 more".
fn list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        _ if items.len() > 5 => format!("{} and {} more", items[..5].join(", "), items.len() - 5),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snippet(name: &str, body: &str, tags: &[&str]) -> CsvSnippet {
        CsvSnippet {
            name: name.into(),
            body: body.into(),
            tags: tags.iter().map(|t| (*t).into()).collect(),
        }
    }

    #[test]
    fn the_example_reads_as_it_says() {
        let csv = read("example.csv", EXAMPLE).unwrap();
        assert!(csv.warnings.is_empty());
        assert_eq!(
            csv.snippets,
            [
                snippet("Disk usage", "df -h", &["linux", "disk"]),
                snippet("Follow the system log", "journalctl -f -n 100", &["linux"]),
                snippet(
                    "Restart nginx",
                    "sudo systemctl restart nginx && systemctl status nginx --no-pager",
                    &["nginx", "web"]
                ),
                snippet(
                    "Database size",
                    "psql -c \"SELECT pg_size_pretty(pg_database_size(current_database()));\"",
                    &["postgres"]
                ),
                snippet(
                    "Deploy",
                    "cd /srv/app\ngit pull --ff-only\n./deploy.sh",
                    &[]
                ),
            ]
        );
    }

    #[test]
    fn columns_by_header_in_any_order_and_separator() {
        // A spreadsheet in a language that writes decimal commas: semicolons, and a byte order mark.
        let csv = read(
            "s.csv",
            "\u{feff}Tags;Script;Title\nops;uptime;Load\n;ls -la;\n",
        )
        .unwrap();
        assert_eq!(
            csv.snippets,
            [
                snippet("Load", "uptime", &["ops"]),
                snippet("ls -la", "ls -la", &[])
            ]
        );
    }

    #[test]
    fn a_command_without_a_name_is_named_by_its_first_line() {
        let long = "find / -xdev -type f -size +100M -printf '%s %p\\n' | sort -n | tail";
        let csv = read("s.csv", &format!("Command\n\"{long}\nwc -l\"\n")).unwrap();
        assert_eq!(
            csv.snippets[0].name,
            "find / -xdev -type f -size +100M -printf…"
        );
        assert_eq!(csv.snippets[0].body, format!("{long}\nwc -l"));
    }

    #[test]
    fn rows_without_a_command_are_left_out_and_said() {
        let csv = read("s.csv", "Name,Command\na,\nb,ls\nc,  \n").unwrap();
        assert_eq!(csv.snippets, [snippet("b", "ls", &[])]);
        assert_eq!(
            csv.warnings,
            ["Lines 2 and 4 have no command, so they're left out."]
        );
    }

    #[test]
    fn a_file_without_a_command_column_says_what_it_needs() {
        let err = read("hosts.csv", "Label,Hostname\nweb,web.example.com\n").unwrap_err();
        assert!(err.contains("no Command column"), "{err}");
        assert_eq!(read("e.csv", "").unwrap_err(), "e.csv is empty");
    }
}
