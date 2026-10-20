//! Terminal appearance: color themes (built into the app, or imported into the vault from other
//! terminals' theme files) and this device's font, cursor and default theme.
//!
//! Imports read the formats theme collections publish: Ghostty, Alacritty (`.toml`), iTerm2
//! (`.itermcolors`) and Windows Terminal (a JSON color scheme). They all hold the same thing (the
//! 16 ANSI colors, background, foreground, cursor and selection), which is what the vault keeps.

use mg_store::{ItemData, TerminalTheme, is_hex_color};
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::util::expand_home;
use crate::vault::VaultState;

/// Device setting holding [`TerminalSettings`] as JSON.
const SETTINGS: &str = "terminal";
/// The scheme a device starts with (Console, the brand's dark scheme).
const DEFAULT_THEME: &str = "builtin:console";

const ANSI_NAMES: [&str; 8] = [
    "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white",
];

/// A theme file in one of the supported formats, as a vault theme named `name`.
pub fn parse(text: &str, name: &str) -> Result<TerminalTheme, String> {
    let t = text.trim_start_matches('\u{feff}').trim();
    let mut theme = if t.starts_with("<?xml") || t.contains("<plist") {
        iterm(t)?
    } else if t.starts_with('{') {
        windows_terminal(t)?
    } else if t.contains("[colors") {
        alacritty(t)?
    } else if t.lines().any(|l| l.trim_start().starts_with("palette")) {
        ghostty(t)?
    } else {
        return Err(
            "not a theme MorphGate can read: use a Ghostty, Alacritty (.toml), iTerm2 \
             (.itermcolors) or Windows Terminal (JSON) theme"
                .into(),
        );
    };
    if theme.name.is_empty() {
        theme.name = name.trim().to_owned();
    }
    if theme.name.is_empty() {
        theme.name = "Imported theme".into();
    }
    Ok(theme)
}

/// `#rrggbb` from `#rrggbb`, `rrggbb`, `0xrrggbb` or `#rgb` (alpha dropped).
fn color(raw: &str) -> Option<String> {
    let s = raw.trim().trim_matches(['"', '\'']);
    let hex = s
        .strip_prefix('#')
        .or_else(|| s.strip_prefix("0x"))
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let hex = match hex.len() {
        3 => hex.chars().flat_map(|c| [c, c]).collect(),
        6 | 8 => hex[..6].to_owned(),
        _ => return None,
    };
    let c = format!("#{}", hex.to_ascii_lowercase());
    is_hex_color(&c).then_some(c)
}

/// Fills in what a format may leave out, and checks the result.
struct Builder {
    name: String,
    background: Option<String>,
    foreground: Option<String>,
    cursor: Option<String>,
    cursor_accent: Option<String>,
    selection_background: Option<String>,
    selection_foreground: Option<String>,
    ansi: [Option<String>; 16],
}

impl Builder {
    fn new() -> Self {
        Self {
            name: String::new(),
            background: None,
            foreground: None,
            cursor: None,
            cursor_accent: None,
            selection_background: None,
            selection_foreground: None,
            ansi: Default::default(),
        }
    }

    fn set(slot: &mut Option<String>, raw: &str) -> Result<(), String> {
        *slot = Some(color(raw).ok_or_else(|| format!("not a color: {raw}"))?);
        Ok(())
    }

    fn build(self) -> Result<TerminalTheme, String> {
        let missing = |what: &str| format!("the theme has no {what} color");
        let background = self.background.ok_or_else(|| missing("background"))?;
        let foreground = self.foreground.ok_or_else(|| missing("foreground"))?;
        let mut ansi = Vec::with_capacity(16);
        for (i, c) in self.ansi.into_iter().enumerate() {
            let name = format!(
                "{}{}",
                if i < 8 { "" } else { "bright " },
                ANSI_NAMES[i % 8]
            );
            ansi.push(c.ok_or_else(|| missing(&name))?);
        }
        Ok(TerminalTheme {
            name: self.name,
            cursor: self.cursor.unwrap_or_else(|| foreground.clone()),
            cursor_accent: self.cursor_accent.unwrap_or_else(|| background.clone()),
            selection_background: self.selection_background.unwrap_or_else(|| ansi[8].clone()),
            selection_foreground: self.selection_foreground,
            background,
            foreground,
            ansi,
        })
    }
}

/// `background = #1e1e2e`, `palette = 0=#45475a`, …
fn ghostty(text: &str) -> Result<TerminalTheme, String> {
    let mut b = Builder::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "background" => Builder::set(&mut b.background, value)?,
            "foreground" => Builder::set(&mut b.foreground, value)?,
            "cursor-color" => Builder::set(&mut b.cursor, value)?,
            "cursor-text" => Builder::set(&mut b.cursor_accent, value)?,
            "selection-background" => Builder::set(&mut b.selection_background, value)?,
            "selection-foreground" => Builder::set(&mut b.selection_foreground, value)?,
            "palette" => {
                let (i, c) = value
                    .split_once('=')
                    .ok_or_else(|| format!("palette entry without a number: {value}"))?;
                let i: usize = i.trim().parse().map_err(|_| format!("palette {i}"))?;
                // 256-color palettes go beyond the 16 a theme defines.
                if i < 16 {
                    Builder::set(&mut b.ansi[i], c)?;
                }
            }
            _ => {}
        }
    }
    b.build()
}

/// `[colors.primary] background = "#…"`, `[colors.normal] black = "#…"`, …
fn alacritty(text: &str) -> Result<TerminalTheme, String> {
    let doc: toml::Table = text.parse().map_err(|e| format!("not valid TOML: {e}"))?;
    let colors = doc
        .get("colors")
        .and_then(|c| c.as_table())
        .ok_or("the TOML has no [colors]")?;
    let get = |section: &str, key: &str| {
        colors
            .get(section)
            .and_then(|s| s.get(key))
            .and_then(|v| v.as_str())
    };
    let mut b = Builder::new();
    // "CellForeground" / "CellBackground" mean "the cell's own color": left to the defaults.
    let set = |slot: &mut Option<String>, v: Option<&str>| match v {
        Some(v) if !v.starts_with("Cell") => Builder::set(slot, v),
        _ => Ok(()),
    };
    set(&mut b.background, get("primary", "background"))?;
    set(&mut b.foreground, get("primary", "foreground"))?;
    set(&mut b.cursor, get("cursor", "cursor"))?;
    set(&mut b.cursor_accent, get("cursor", "text"))?;
    set(&mut b.selection_background, get("selection", "background"))?;
    set(&mut b.selection_foreground, get("selection", "text"))?;
    for (i, name) in ANSI_NAMES.iter().enumerate() {
        set(&mut b.ansi[i], get("normal", name))?;
        set(&mut b.ansi[i + 8], get("bright", name))?;
    }
    b.build()
}

/// A property list of `Ansi 0 Color` … `Ansi 15 Color`, `Background Color`, … with float
/// components.
fn iterm(text: &str) -> Result<TerminalTheme, String> {
    let plist = plist::Value::from_reader_xml(text.as_bytes())
        .map_err(|e| format!("not a valid .itermcolors file: {e}"))?;
    let dict = plist.as_dictionary().ok_or("not a color dictionary")?;
    let get = |key: &str| -> Result<Option<String>, String> {
        let Some(c) = dict.get(key).and_then(|v| v.as_dictionary()) else {
            return Ok(None);
        };
        let part = |k: &str| {
            c.get(k)
                .and_then(|v| {
                    v.as_real()
                        .or_else(|| v.as_signed_integer().map(|i| i as f64))
                })
                .ok_or_else(|| format!("{key}: no {k}"))
        };
        let byte = |x: f64| (x.clamp(0.0, 1.0) * 255.0).round() as u8;
        let (r, g, b) = (
            part("Red Component")?,
            part("Green Component")?,
            part("Blue Component")?,
        );
        Ok(Some(format!(
            "#{:02x}{:02x}{:02x}",
            byte(r),
            byte(g),
            byte(b)
        )))
    };
    let mut b = Builder::new();
    b.background = get("Background Color")?;
    b.foreground = get("Foreground Color")?;
    b.cursor = get("Cursor Color")?;
    b.cursor_accent = get("Cursor Text Color")?;
    b.selection_background = get("Selection Color")?;
    b.selection_foreground = get("Selected Text Color")?;
    for i in 0..16 {
        b.ansi[i] = get(&format!("Ansi {i} Color"))?;
    }
    b.build()
}

/// `{"name": …, "background": "#…", "black": "#…", "brightPurple": "#…", …}`, or a
/// settings file's `{"schemes": [ … ]}` (the first scheme).
fn windows_terminal(text: &str) -> Result<TerminalTheme, String> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let scheme = match v.get("schemes").and_then(|s| s.as_array()) {
        Some(list) => list.first().ok_or("the file has no color schemes")?,
        None => &v,
    };
    let get = |key: &str| scheme.get(key).and_then(|v| v.as_str());
    let mut b = Builder::new();
    let set = |slot: &mut Option<String>, v: Option<&str>| match v {
        Some(v) => Builder::set(slot, v),
        None => Ok(()),
    };
    set(&mut b.background, get("background"))?;
    set(&mut b.foreground, get("foreground"))?;
    set(&mut b.cursor, get("cursorColor"))?;
    set(&mut b.selection_background, get("selectionBackground"))?;
    for (i, name) in ANSI_NAMES.iter().enumerate() {
        // Windows Terminal calls magenta "purple".
        let alt = if *name == "magenta" { "purple" } else { name };
        set(&mut b.ansi[i], get(name).or_else(|| get(alt)))?;
        let bright = |n: &str| format!("bright{}{}", n[..1].to_uppercase(), &n[1..]);
        set(
            &mut b.ansi[i + 8],
            get(&bright(name)).or_else(|| get(&bright(alt))),
        )?;
    }
    b.name = get("name").unwrap_or_default().trim().to_owned();
    b.build()
}

/// "catppuccin-mocha.itermcolors" → "Catppuccin Mocha".
fn name_from_path(path: &str) -> String {
    let file = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let stem = file.split_once('.').map_or(file, |(s, _)| s);
    stem.split(['-', '_', ' '])
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut c = w.chars();
            c.next()
                .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ------------------------------------------------------------------ commands

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThemeView {
    id: String,
    vault_id: String,
    name: String,
    background: String,
    foreground: String,
    cursor: String,
    cursor_accent: String,
    selection_background: String,
    selection_foreground: Option<String>,
    ansi: Vec<String>,
}

fn view(id: String, vault_id: String, t: TerminalTheme) -> ThemeView {
    ThemeView {
        id,
        vault_id,
        name: t.name,
        background: t.background,
        foreground: t.foreground,
        cursor: t.cursor,
        cursor_accent: t.cursor_accent,
        selection_background: t.selection_background,
        selection_foreground: t.selection_foreground,
        ansi: t.ansi,
    }
}

/// Themes in the vault (the built-in ones are the app's own).
#[tauri::command]
pub fn themes_list(vault: State<'_, VaultState>) -> Result<Vec<ThemeView>, String> {
    let mut out: Vec<ThemeView> = vault
        .guard()?
        .items()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter_map(|i| match i.data {
            ItemData::TerminalTheme(t) => Some(view(i.id, i.vault_id, t)),
            _ => None,
        })
        .collect();
    out.sort_by_key(|t| t.name.to_lowercase());
    Ok(out)
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ThemeSource {
    Text { text: String },
    File { path: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThemeImport {
    source: ThemeSource,
    /// Empty: the file's name (or the name inside it).
    #[serde(default)]
    name: String,
    /// The vault to keep it in (default: personal).
    #[serde(default)]
    vault_id: Option<String>,
}

#[tauri::command]
pub fn theme_import(vault: State<'_, VaultState>, input: ThemeImport) -> Result<ThemeView, String> {
    let (text, hint) = match input.source {
        ThemeSource::Text { text } => (text, String::new()),
        ThemeSource::File { path } => {
            let path = expand_home(path.trim());
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            (text, name_from_path(&path.to_string_lossy()))
        }
    };
    let mut theme = parse(&text, &hint)?;
    if !input.name.trim().is_empty() {
        theme.name = input.name.trim().to_owned();
    }
    let item = crate::vault::save(
        &mut *vault.guard()?,
        None,
        input.vault_id.as_deref(),
        ItemData::TerminalTheme(theme),
    )
    .map_err(|e| e.to_string())?;
    vault.changed();
    match item.data {
        ItemData::TerminalTheme(t) => Ok(view(item.id, item.vault_id, t)),
        _ => unreachable!("save returns the data it was given"),
    }
}

#[tauri::command]
pub fn theme_delete(vault: State<'_, VaultState>, id: String) -> Result<(), String> {
    vault.guard()?.delete(&id).map_err(|e| e.to_string())?;
    vault.changed();
    Ok(())
}

/// This device's appearance: the app theme, and the terminal's default scheme, font and cursor
/// (not synced: screens, rooms and installed fonts differ).
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TerminalSettings {
    /// `dark` (Console), `light` (Greenbar) or `system`.
    app_theme: String,
    /// A built-in theme (`builtin:…`) or a vault theme's id.
    theme: String,
    /// Console while the app is dark, Greenbar while it is light (instead of `theme`).
    follow_app_theme: bool,
    /// CSS font list; empty = the app's.
    font_family: String,
    font_size: u16,
    /// `block`, `bar` or `underline`.
    cursor_style: String,
    cursor_blink: bool,
    /// Bold text in the bright colors.
    bold_bright: bool,
    /// Lighten or darken colors too close to their background to this ratio; `None` = the
    /// scheme's own.
    minimum_contrast: Option<f32>,
}

impl Default for TerminalSettings {
    fn default() -> Self {
        Self {
            app_theme: "dark".into(),
            theme: DEFAULT_THEME.into(),
            follow_app_theme: false,
            font_family: String::new(),
            font_size: 14,
            cursor_style: "block".into(),
            cursor_blink: true,
            bold_bright: false,
            minimum_contrast: None,
        }
    }
}

#[tauri::command]
pub fn terminal_settings(vault: State<'_, VaultState>) -> Result<TerminalSettings, String> {
    Ok(vault
        .guard()?
        .setting(SETTINGS)
        .map_err(|e| e.to_string())?
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default())
}

#[tauri::command]
pub fn terminal_settings_set(
    vault: State<'_, VaultState>,
    settings: TerminalSettings,
) -> Result<(), String> {
    if !(6..=48).contains(&settings.font_size) {
        return Err("font size must be between 6 and 48".into());
    }
    if !["block", "bar", "underline"].contains(&settings.cursor_style.as_str()) {
        return Err("cursor style must be block, bar or underline".into());
    }
    if !["dark", "light", "system"].contains(&settings.app_theme.as_str()) {
        return Err("the app theme must be dark, light or system".into());
    }
    if settings
        .minimum_contrast
        .is_some_and(|c| !(1.0..=21.0).contains(&c))
    {
        return Err("minimum contrast must be between 1 and 21".into());
    }
    let raw = serde_json::to_string(&settings).map_err(|e| e.to_string())?;
    vault
        .guard()?
        .set_setting(SETTINGS, Some(&raw))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same made-up theme in every format.
    const BG: &str = "#101418";
    const FG: &str = "#d0d8e0";

    fn ansi() -> Vec<String> {
        (0..16)
            .map(|i| format!("#{:02x}{:02x}{:02x}", 16 * i, 255 - 8 * i, i))
            .collect()
    }

    fn check(t: &TerminalTheme) {
        assert_eq!((t.background.as_str(), t.foreground.as_str()), (BG, FG));
        assert_eq!(t.ansi, ansi());
        assert_eq!(t.cursor, "#ffaa00");
    }

    #[test]
    fn ghostty() {
        let mut text = format!(
            "# a comment\nbackground = {BG}\nforeground = d0d8e0\ncursor-color = #FFAA00\n\
             cursor-text = #000000\nselection-background = #334455\n"
        );
        for (i, c) in ansi().iter().enumerate() {
            text += &format!("palette = {i}={c}\n");
        }
        text += "palette = 200=#123456\n";
        let t = parse(&text, "Mine").unwrap();
        check(&t);
        assert_eq!(t.name, "Mine");
        assert_eq!(t.cursor_accent, "#000000");
        assert_eq!(t.selection_background, "#334455");
        assert_eq!(t.selection_foreground, None);
    }

    #[test]
    fn alacritty() {
        let a = ansi();
        let mut text = format!(
            "[colors.primary]\nforeground = \"{FG}\"\nbackground = \"0x101418\"\n\n\
             [colors.cursor]\ntext = \"CellBackground\"\ncursor = \"#ffaa00\"\n\n\
             [colors.selection]\ntext = \"CellForeground\"\nbackground = \"#334455\"\n"
        );
        for (section, offset) in [("normal", 0), ("bright", 8)] {
            text += &format!("\n[colors.{section}]\n");
            for (i, n) in ANSI_NAMES.iter().enumerate() {
                text += &format!("{n} = \"{}\"\n", a[i + offset]);
            }
        }
        let t = parse(&text, "Alacritty One").unwrap();
        check(&t);
        // "CellBackground" / "CellForeground" aren't colors: the defaults apply.
        assert_eq!(t.cursor_accent, BG);
        assert_eq!(t.selection_foreground, None);
    }

    #[test]
    fn iterm2() {
        let comp = |hex: &str| {
            let v = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).unwrap() as f64 / 255.0;
            format!(
                "<dict><key>Color Space</key><string>sRGB</string>\
                 <key>Red Component</key><real>{}</real><key>Green Component</key><real>{}</real>\
                 <key>Blue Component</key><real>{}</real></dict>",
                v(1),
                v(3),
                v(5)
            )
        };
        let mut body = String::new();
        for (i, c) in ansi().iter().enumerate() {
            body += &format!("<key>Ansi {i} Color</key>{}", comp(c));
        }
        body += &format!("<key>Background Color</key>{}", comp(BG));
        body += &format!("<key>Foreground Color</key>{}", comp(FG));
        body += &format!("<key>Cursor Color</key>{}", comp("#ffaa00"));
        body += &format!("<key>Selected Text Color</key>{}", comp("#ffffff"));
        let text = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>{body}</dict></plist>"
        );
        let t = parse(&text, "iTerm One").unwrap();
        check(&t);
        assert_eq!(t.selection_foreground.as_deref(), Some("#ffffff"));
        // No selection color in the file: bright black stands in.
        assert_eq!(t.selection_background, ansi()[8]);
    }

    #[test]
    fn windows_terminal() {
        let a = ansi();
        let names = [
            "black", "red", "green", "yellow", "blue", "purple", "cyan", "white",
        ];
        let mut fields = vec![
            "\"name\": \"Campbell Plus\"".to_owned(),
            format!("\"background\": \"{BG}\""),
            format!("\"foreground\": \"{FG}\""),
            "\"cursorColor\": \"#FFAA00\"".to_owned(),
        ];
        for (i, n) in names.iter().enumerate() {
            fields.push(format!("\"{n}\": \"{}\"", a[i]));
            let bright = format!("bright{}{}", n[..1].to_uppercase(), &n[1..]);
            fields.push(format!("\"{bright}\": \"{}\"", a[i + 8]));
        }
        let scheme = format!("{{{}}}", fields.join(", "));
        let t = parse(&scheme, "ignored").unwrap();
        check(&t);
        assert_eq!(t.name, "Campbell Plus");
        let settings = format!("{{\"schemes\": [{scheme}]}}");
        check(&parse(&settings, "").unwrap());
    }

    #[test]
    fn what_is_refused() {
        assert!(
            parse("just some text", "x")
                .unwrap_err()
                .contains("Ghostty")
        );
        // A theme missing a color says which.
        let err = parse(
            &format!("background = {BG}\nforeground = {FG}\npalette = 0=#000000"),
            "x",
        )
        .unwrap_err();
        assert!(err.contains("red"), "{err}");
        assert!(parse("background = blue\npalette = 0=#000000", "x").is_err());
    }

    #[test]
    fn colors_and_names() {
        assert_eq!(color("#ABC").as_deref(), Some("#aabbcc"));
        assert_eq!(color("0x1E1E2E").as_deref(), Some("#1e1e2e"));
        assert_eq!(color("#1e1e2eff").as_deref(), Some("#1e1e2e"));
        assert_eq!(color("\"#1e1e2e\"").as_deref(), Some("#1e1e2e"));
        assert_eq!(color("blue"), None);
        assert_eq!(
            name_from_path("/tmp/catppuccin-mocha.itermcolors"),
            "Catppuccin Mocha"
        );
        assert_eq!(
            name_from_path("C:\\themes\\tokyo_night.json"),
            "Tokyo Night"
        );
    }
}
