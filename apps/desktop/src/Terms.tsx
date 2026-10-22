import { openLink, type SyncTerms } from "./api";

/** The server's terms of use and privacy policy, each opening in the browser. */
export function TermsLinks({ terms }: { terms: SyncTerms }) {
  return (
    <>
      <button type="button" className="link inline" onClick={() => void openLink(terms.termsUrl)}>
        terms of use
      </button>{" "}
      and the{" "}
      <button type="button" className="link inline" onClick={() => void openLink(terms.privacyUrl)}>
        privacy policy
      </button>
    </>
  );
}

export function TermsCheck({ terms, accepted, onChange }: { terms: SyncTerms; accepted: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="check terms-check">
      <input type="checkbox" checked={accepted} onChange={(e) => onChange(e.target.checked)} />
      <span>
        I accept the <TermsLinks terms={terms} />.
      </span>
    </label>
  );
}
