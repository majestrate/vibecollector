import { useEffect, useState, type FormEvent, type ReactElement } from "react";
import { useNavigate } from "react-router-dom";
import { clearAuthError, consumeReturn, dropSession, peekAuthError, startLogin } from "./auth";
import { accessToken, clientCreds, saveClientCreds } from "./session";

/**
 * CredentialsForm collects the OAuth client id and secret for this tab.
 * Submit stores the pair in sessionStorage and starts the authorization-code grant.
 * The access token is not stored. An empty id or secret is rejected.
 */
export function CredentialsForm(): ReactElement {
  const nav = useNavigate();
  const saved = clientCreds();
  const [clientId, setClientId] = useState(saved?.clientId ?? "");
  const [clientSecret, setClientSecret] = useState(saved?.clientSecret ?? "");
  const [error, setError] = useState<string | null>(() => peekAuthError());

  useEffect(() => {
    clearAuthError();
  }, []);

  function onSubmit(event: FormEvent): void {
    event.preventDefault();
    const id = clientId.trim();
    if (id === "" || clientSecret === "") {
      setError("Enter a client id and a client secret.");
      return;
    }
    try {
      saveClientCreds(id, clientSecret);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not store the credentials.");
      return;
    }
    dropSession();
    void startLogin().catch((err: unknown) => {
      setError(err instanceof Error ? err.message : "Sign-in failed.");
    });
  }

  return (
    <>
      <header className="top">
        <strong>VibeCollector</strong>
      </header>
      <form className="credentials" onSubmit={onSubmit}>
        <h1>Client credentials</h1>
        <p>These stay in this tab. The page uses them to sign in with PKCE.</p>
        {error ? <p className="warn">{error}</p> : null}
        <label>
          Client id
          <input name="client_id" value={clientId} autoComplete="username" onChange={(e) => setClientId(e.target.value)} />
        </label>
        <label>
          Client secret
          <input
            name="client_secret"
            type="password"
            value={clientSecret}
            autoComplete="current-password"
            onChange={(e) => setClientSecret(e.target.value)}
          />
        </label>
        <div className="actions">
          <button type="submit">Save</button>
          {accessToken() ? (
            <button type="button" onClick={() => nav(consumeReturn())}>
              Back
            </button>
          ) : null}
        </div>
      </form>
    </>
  );
}
