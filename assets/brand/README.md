# Brand files

From the MorphGate Brand design system: the mark (a gate: arch, `>` prompt, amber block cursor on
the threshold), lockups and app icon tiles. Use them as they are; never redraw the mark or retype
the wordmark in a live font.

| File | Use |
| --- | --- |
| `morphgate-app-icon.svg` | App icon, favicon, social avatar (Console tile). The app's icons in `apps/desktop/src-tauri/icons` are generated from it with `npx tauri icon`. |
| `morphgate-app-icon-mint.svg` | Only where the dark tile disappears (dark docks, dark store listings). |
| `morphgate-app-icon-ios.svg` | The iOS icon: the same tile full-bleed and square (iOS cuts the corners itself). |
| `morphgate-android-foreground.svg`, `-background.svg`, `-monochrome.svg` | Android's adaptive icon layers: the mark alone, scaled to stay inside the circle launchers cut, on the tile's colour; one-colour for themed icons. |
| `morphgate-lockup-on-dark.svg` | On dark grounds (Console, terminal backgrounds). |
| `morphgate-lockup-on-light.svg` | On light grounds (Greenbar, paper). |
| `morphgate-social-preview.png` | The repository's social preview on GitHub (Settings → General → Social preview), 1280 × 640: the lockup on the dark ground, the tagline, the platforms. |

The phone icons come from `icon-manifest.json` (Android) and the iOS tile, and go to both
`src-tauri/icons` and the generated projects (`gen/android`, `gen/apple`), which `tauri icon`
doesn't write to:

```sh
cd apps/desktop
npx tauri icon ../../assets/brand/icon-manifest.json -o /tmp/icons   # copy android/ from here
npx tauri icon ../../assets/brand/morphgate-app-icon-ios.svg -o /tmp/icons-ios   # and ios/
```

In the app, `apps/desktop/src/Logo.tsx` draws the mark and lockup inline in the theme's tokens.
