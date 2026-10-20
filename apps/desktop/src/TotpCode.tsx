/** The 6-digit code from an authenticator app: digits only, filled by password managers. */
export function TotpCode({
  value,
  onChange,
  label = "Authenticator code",
  autoFocus = true,
}: {
  value: string;
  onChange: (code: string) => void;
  label?: string;
  autoFocus?: boolean;
}) {
  return (
    <label>
      <span>{label}</span>
      <input
        className="mono totp-code"
        value={value}
        onChange={(e) => onChange(e.target.value.replace(/\D/g, "").slice(0, 6))}
        inputMode="numeric"
        autoComplete="one-time-code"
        placeholder="123456"
        autoFocus={autoFocus}
      />
    </label>
  );
}

export const isTotpCode = (code: string) => /^\d{6}$/.test(code);
