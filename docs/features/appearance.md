# Appearance

How the app and its terminals look: the app theme (dark Console, light Greenbar, or the system's), seven built-in terminal color schemes, schemes imported from other terminals' theme files, the terminal font, cursor and minimum contrast, and a scheme per host. The device's choices stay on the device, because screens, rooms and installed fonts differ; imported schemes and a host's scheme live in the vault and sync, so a team's production hosts look like production on every member's screen. Code: `apps/desktop/src-tauri/src/themes.rs` (theme parsing, Tauri commands, `TerminalSettings`), `apps/desktop/src/themes.ts` (built-in schemes, `findTheme()`), `apps/desktop/src/AppearancePanel.tsx`, `useAppTheme()` and `lookFor()` in `apps/desktop/src/App.tsx`, `TerminalTheme` in `crates/mg-store/src/model.rs`.

## Where it is

On desktop, the settings icon at the top of the sidebar (labelled "Settings", tooltip "Settings: app theme and terminal appearance"); on phones, More → **Settings**. The page is headed "Settings / Terminal appearance" with "Applies to every host without its own scheme. A host can set one in its editor." Every control saves at once (`terminal_settings_set`); there is no Save button. A preview on the right ("Preview · {scheme}") shows a few lines of a session in the chosen scheme, font, cursor and bold setting, and the built-in scheme's description.

## Controls

| Section | Control | Does |
| --- | --- | --- |
| App theme | **Console**, **Greenbar**, **Like the system** | `appTheme`: `dark`, `light` or `system` |
| Scheme | **Follow the app theme** ("Console while the app is dark, Greenbar while it is light.") | `followAppTheme`; picking a scheme card turns it off |
| Scheme | Scheme cards (built-in first, then the vault's) | `theme`: the card's id. Picking one also resets minimum contrast to the scheme's own. An imported card is tagged "Imported" (personal vault) or with its vault's name |
| Scheme | **×** on an imported card, then **Delete?** | `theme_delete`; only for schemes in a vault the person can write. Deleting the device's scheme switches the device to Console |
| Font | **Family**: Atkinson Hyperlegible Mono (default), JetBrains Mono, Fira Code, System monospace, **Another installed font…** | `fontFamily`: a CSS font list; empty is the default |
| Font | **Another installed font…** → a name field (placeholder "Cascadia Code") and **Use font** | `fontFamily` becomes `"<name>", monospace` |
| Font | **Size**: **−** and **+** | `fontSize`, 10 to 24 px in the panel |
| Cursor and text | **Block**, **Bar**, **Underline**; **Blink** | `cursorStyle`, `cursorBlink` |
| Cursor and text | **Draw bold text in bright colors** | `boldBright` |
| Minimum contrast | Slider "Minimum contrast ratio", 1 to 7 in steps of 0.5, marked "1 off", "4.5 AA", "7 AAA" | `minimumContrast`. A note says what the ratio means ("Off: colors are drawn exactly as the program asks.", "At 4.5:1 text meets WCAG AA.", …) |
| Minimum contrast | **Use the scheme's own (N:1)** | `minimumContrast: null` |
| | **Import a scheme…** | Opens the import form ([below](#imported-schemes)) |
| | **Reset to defaults** | Every terminal setting back to its default; the app theme stays |
| | **Close** | Back to the workspace |

## App themes

`useAppTheme()` sets `data-theme="dark"` or `"light"` on the document element, and `tokens.css` holds both palettes. **Like the system** follows `prefers-color-scheme` and changes with it. Device settings can be read while the vault is locked, so the unlock screen already uses the chosen theme.

## Built-in schemes

From the MorphGate brand design system (`terminal-schemes.json`), in `BUILTIN_THEMES`. Every ANSI color except black reaches the scheme's minimum contrast against its background; the 256-color cube and grey ramp keep their xterm values, and 24-bit color passes through.

| Id | Name | Style | Minimum contrast |
| --- | --- | --- | --- |
| `builtin:console` | Console | Brand dark; the default (`DEFAULT_THEME`) | 4.5 |
| `builtin:greenbar` | Greenbar | Brand light | 4.5 |
| `builtin:phosphor` | Phosphor P1 | Retro monochrome (green) | 4.5 |
| `builtin:sodium` | Sodium P3 | Retro monochrome (amber) | 4.5 |
| `builtin:bastion` | Bastion | High contrast | 7 |
| `builtin:dusk` | Dusk | Low glare | 4.5 |
| `builtin:production` | Production | Per-host warning | 4.5 |

Ids are what hosts and settings store, so they never change once released. A tab whose scheme is `builtin:production` (`PRODUCTION_THEME`) also gets a **PROD** label, on desktop tabs and phone session cards, so color is never the only signal.

## How a session picks its scheme

1. The host's own scheme (`theme_ref`), else its group's ([Hosts, groups and identities](hosts-groups-identities.md)). The host editor's **Terminal scheme** select offers "This device's scheme" (or "From the group: {name}"), the built-in schemes, and the schemes in the host's own vault.
2. Otherwise the device's: Console or Greenbar while **Follow the app theme** is on, else the chosen scheme.
3. A scheme that no longer exists falls back to Console (`findTheme()`).

Minimum contrast is the device's setting when set, else the built-in scheme's own, else 1 (off): imported schemes have none of their own, so their colors are drawn as they are. Session logs play back in the device's scheme ([Session logs](session-logs.md)). Fonts, cursor and bold come from the device for every session.

## Imported schemes

**Import a scheme…** opens a form: **From file** or **Paste**; **Theme file** (a path, e.g. `~/Downloads/catppuccin-mocha.itermcolors`) or **Theme** (the file's text); **Name** ("From the file"); the vault to keep it in; **Cancel** and **Import and use**, which imports and makes it the device's scheme.

`themes::parse()` recognizes the format from the text:

| Recognized by | Format | Read |
| --- | --- | --- |
| `<?xml` or `<plist` | iTerm2 (`.itermcolors`) | `Ansi 0 Color` … `Ansi 15 Color`, `Background Color`, `Foreground Color`, `Cursor Color`, `Cursor Text Color`, `Selection Color`, `Selected Text Color`; float components to `#rrggbb` |
| Starts with `{` | Windows Terminal (JSON) | `background`, `foreground`, `cursorColor`, `selectionBackground`, `black` … `brightWhite` (`purple` for magenta), `name`; a settings file's `schemes` array gives its first scheme |
| Contains `[colors` | Alacritty (TOML) | `[colors.primary]`, `[colors.cursor]`, `[colors.selection]`, `[colors.normal]`, `[colors.bright]`; `CellForeground`/`CellBackground` are left to the defaults |
| A line starting with `palette` | Ghostty | `background`, `foreground`, `cursor-color`, `cursor-text`, `selection-background`, `selection-foreground`, `palette = N=#…` (entries above 15 ignored) |

Colors may be `#rrggbb`, `rrggbb`, `0xrrggbb` or `#rgb`; an alpha byte is dropped. What a file leaves out is filled in: the cursor takes the foreground, the character under it the background, the selection bright black, and the selection's text keeps its own colors. The name is the one typed, else the one in the file (Windows Terminal), else the file's name ("catppuccin-mocha.itermcolors" → "Catppuccin Mocha"), else "Imported theme".

| Error | Cause |
| --- | --- |
| "not a theme MorphGate can read: use a Ghostty, Alacritty (.toml), iTerm2 (.itermcolors) or Windows Terminal (JSON) theme" | No format recognized |
| "the theme has no {background, foreground, red, bright cyan, …} color" | A required color is missing; all 16 ANSI colors are required |
| "not a color: …" | A value that is not a hex color |
| "not valid TOML: …", "the TOML has no [colors]", "not a valid .itermcolors file: …", "not valid JSON: …", "the file has no color schemes", "palette entry without a number: …" | The file itself |
| "a theme needs a name", "a theme needs #rrggbb colors and 16 ANSI colors" | The vault's check on save (`mg-store`) |
| `terminal theme "{name}" is still used by: {hosts, groups}` | Deleting a scheme a host or group in its vault still uses |
| "the selected terminal theme does not exist" | Saving a host or group with a scheme that isn't in its vault |

An imported scheme is a `terminal_theme` vault item: `name`, `background`, `foreground`, `cursor`, `cursor_accent`, `selection_background`, optional `selection_foreground`, and `ansi` (16 colors: black, red, green, yellow, blue, magenta, cyan, white, then the same eight bright). A host can use only a scheme from its own vault, or a built-in one, so a shared host never points at someone's personal scheme.

## Tauri commands

| Command | Does |
| --- | --- |
| `themes_list` | The vault's `terminal_theme` items, sorted by name |
| `theme_import` | `{source: {kind: "text", text} \| {kind: "file", path}, name, vaultId}`: parses, saves into the vault (personal by default), returns the scheme |
| `theme_delete` | Deletes a scheme item |
| `terminal_settings` | This device's `TerminalSettings`, or the defaults |
| `terminal_settings_set` | Saves them, after checking: "font size must be between 6 and 48", "cursor style must be block, bar or underline", "the app theme must be dark, light or system", "minimum contrast must be between 1 and 21" |

## What syncs and what stays on the device

| What | Stored | Syncs |
| --- | --- | --- |
| App theme, device scheme, follow the app theme, font family and size, cursor style and blink, bold in bright colors, minimum contrast | `TerminalSettings` as JSON in the `settings` table of `vault.sqlite3`, key `terminal`, in plain text (no secrets; readable while locked) | No |
| Imported schemes | `terminal_theme` items in their vault, encrypted | Yes, with their vault; in a team vault, to the team |
| A host's or group's scheme | `theme_ref` on the host or group item | Yes |

Defaults (`TerminalSettings::default()`): app theme dark, scheme `builtin:console`, not following the app theme, the default font, 14 px, block cursor that blinks, bold not bright, the scheme's own contrast.

The fonts are bundled (`apps/desktop/src/assets/fonts/`, SIL Open Font License): Atkinson Hyperlegible Mono for the terminal and for hosts, keys and fingerprints, Atkinson Hyperlegible Next for the interface, Martian Mono for titles. The terminal's default stack is `"Atkinson Hyperlegible Mono", "JetBrains Mono", "Fira Code", ui-monospace, monospace` (`DEFAULT_FONT`). JetBrains Mono, Fira Code and a typed font must be installed on the device; the browser engine falls back down the list otherwise.

## Tests

| Test | Covers |
| --- | --- |
| `themes.rs` `ghostty`, `alacritty`, `iterm2`, `windows_terminal` | The same made-up scheme read from each format, with its defaults (Alacritty's `Cell…` values, iTerm2 without a selection color, a Windows Terminal settings file) |
| `themes.rs` `what_is_refused`, `colors_and_names` | Unknown text, a missing color named in the error, color spellings, names from file paths |
| `mg-store` `terminal_themes_and_the_hosts_that_use_them` | The vault's checks: 16 colors, hex only, a name; a host may use a vault scheme or a built-in one; a scheme in use can't be deleted |
| `apps/desktop/e2e/appimage.mjs` | Picks Bastion and the open terminal repaints; pastes a Ghostty scheme, which becomes the device's, and the terminal follows |

## Limits

- Import takes a typed path or pasted text; there is no file picker.
- The panel offers sizes 10 to 24 px and contrast 1 to 7, though the Rust side accepts 6 to 48 and 1 to 21.
- Schemes can be imported and deleted, not edited in the app.
- There is no per-host font, cursor or contrast; only the scheme is per host.
