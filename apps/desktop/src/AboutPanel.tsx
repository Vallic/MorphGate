import { useEffect, useState } from "react";
import { dateText, device, errorText, updates, type About, type UpdateInfo, type UpdateProgress } from "./api";
import { Licenses } from "./Licenses";
import { Logo } from "./Logo";
import { mobileOs, onIos } from "./mobile/useMobile";

interface Props {
  /** The update found by the last check, if any. */
  update: UpdateInfo | null;
  onUpdate: (u: UpdateInfo | null) => void;
  /** Looking for updates by itself was turned on or off. */
  onAutoCheckChanged: (on: boolean) => void;
  onClose: () => void;
}

const PACKAGE_NAMES: Record<NonNullable<About["package"]>, string> = {
  appimage: "AppImage",
  deb: "Debian package",
  rpm: "RPM package",
  app: "macOS app",
  dmg: "macOS app",
  msi: "Windows installer (MSI)",
  nsis: "Windows installer",
};

const mib = (n: number) => `${(n / 1048576).toFixed(1)} MiB`;

/** Version, and updates from MorphGate's releases. */
export function AboutPanel({ update, onUpdate, onAutoCheckChanged, onClose }: Props) {
  const [about, setAbout] = useState<About | null>(null);
  const [autoCheck, setAutoCheck] = useState(true);
  const [checking, setChecking] = useState(false);
  const [checked, setChecked] = useState(false);
  const [progress, setProgress] = useState<UpdateProgress | null>(null);
  const [error, setError] = useState("");
  const [licenses, setLicenses] = useState(false);

  useEffect(() => {
    updates.about().then(setAbout, (e) => setError(errorText(e)));
    device.status().then((d) => setAutoCheck(d.autoUpdateCheck), () => {});
  }, []);

  const check = () => {
    setChecking(true);
    setError("");
    updates
      .check()
      .then((u) => (onUpdate(u), setChecked(true)))
      .catch((e) => setError(errorText(e)))
      .finally(() => setChecking(false));
  };

  const install = () => {
    setError("");
    setProgress({ kind: "downloading", downloaded: 0, total: null });
    // On success MorphGate restarts; this only returns on failure.
    updates.install(setProgress).catch((e) => (setProgress(null), setError(errorText(e))));
  };

  const toggleAuto = (on: boolean) =>
    device.setAutoUpdateCheck(on).then(
      () => (setAutoCheck(on), onAutoCheckChanged(on)),
      (e) => setError(errorText(e)),
    );

  const installable = !!about?.package;
  const pct = progress?.kind === "downloading" && progress.total ? Math.round((progress.downloaded / progress.total) * 100) : progress?.kind === "installing" ? 100 : 0;

  if (licenses) {
    return (
      <div className="panel">
        <div className="panel-card wide">
          <Licenses onBack={() => setLicenses(false)} />
        </div>
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="panel-card">
        <div className="about-head">
          <div>
            <h1 className="about-title">
              <Logo size={30} />
            </h1>
            <p className="hint">
              {about
                ? `Version ${about.version}${about.package ? ` · ${PACKAGE_NAMES[about.package]}` : mobileOs ? "" : " · development build"}`
                : "…"}
            </p>
          </div>
        </div>
        <p className="hint">SSH client with an end-to-end encrypted vault. Free software under the Mozilla Public License 2.0 · morphgate.com</p>
        <button type="button" className="link align-start" onClick={() => setLicenses(true)}>
          Open-source licenses
        </button>
        <hr className="divider" />
        <h2 className="section-title">Updates</h2>
        {mobileOs ? (
          <p className="hint">{onIos ? "MorphGate updates through the App Store." : "MorphGate updates through Google Play, or by installing the next APK."}</p>
        ) : (
          <>
            <label className="check">
              <input type="checkbox" checked={autoCheck} onChange={(e) => void toggleAuto(e.target.checked)} />
              <span>Check for updates automatically</span>
            </label>
            <p className="hint">At launch and twice a day MorphGate asks GitHub for the latest release. Nothing from your vault is sent. Updates are signed, and MorphGate installs only ones signed with its key.</p>

            {update ? (
              <div className="notice-box stack">
                <strong>MorphGate {update.version} is available</strong>
                {update.date && <small className="hint">Released {dateText(update.date)}</small>}
                {update.notes && <div className="pre-line update-notes">{update.notes}</div>}
                {progress ? (
                  <div className="stack">
                    <div className="bar">
                      <i style={{ width: `${pct}%` }} />
                    </div>
                    <small className="hint">
                      {progress.kind === "installing"
                        ? "Installing… MorphGate restarts when it's done."
                        : `Downloading… ${mib(progress.downloaded)}${progress.total ? ` of ${mib(progress.total)}` : ""}`}
                    </small>
                  </div>
                ) : installable ? (
                  <>
                    <p className="hint">
                      Open terminals, file browsers, tunnels and VPNs close when MorphGate restarts.
                      {(about?.package === "deb" || about?.package === "rpm") && " Installing a package asks for an administrator password."}
                    </p>
                    <div className="actions">
                      <span className="spacer" />
                      {/* Install takes the update the last finished check found. */}
                      <button type="button" className="primary" disabled={checking} onClick={install}>
                        Install and restart
                      </button>
                    </div>
                  </>
                ) : (
                  <p className="hint">This is a development build, which can't update itself. Install a release package to get updates.</p>
                )}
              </div>
            ) : (
              checked && !error && <p className="ok">MorphGate is up to date.</p>
            )}
            {error && <p className="error">{error}</p>}
          </>
        )}

        <div className="actions">
          {!mobileOs && (
            <button type="button" className="secondary" disabled={checking || !!progress} onClick={check}>
              {checking ? "Checking…" : "Check now"}
            </button>
          )}
          <span className="spacer" />
          <button type="button" className="secondary" disabled={!!progress} onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
