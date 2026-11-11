import { useEffect, useRef, useState, type ReactElement } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { prefixFromSpec } from "./api";
import { finishCallback, setAuthError, startLogin, rememberReturn } from "./auth";
import { CredentialsForm } from "./credentials";
import { accessToken, clientCreds, hasAPIPrefix, setAPIPrefix } from "./session";
import { Shell } from "./shell";

/**
 * App loads the OpenAPI prefix and signs the shell in with PKCE.
 * A tab with no client id and secret opens the credentials form.
 * The access token stays in memory.
 */
export function App(): ReactElement {
  const location = useLocation();
  const nav = useNavigate();
  const navRef = useRef(nav);
  navRef.current = nav;
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancel = false;
    if (location.pathname !== "/credentials" && !accessToken()) {
      setReady(false);
    }
    (async () => {
      try {
        if (!hasAPIPrefix()) {
          const res = await fetch("/openapi.json", { headers: { Accept: "application/json" } });
          if (cancel) return;
          if (!res.ok) throw new Error("The API document is unavailable.");
          const spec: unknown = await res.json();
          if (cancel) return;
          setAPIPrefix(prefixFromSpec(spec));
        }
        if (cancel) return;
        const path = window.location.pathname;
        const params = new URLSearchParams(window.location.search);
        if (path === "/credentials") {
          setError(null);
          setReady(true);
          return;
        }
        if (path === "/callback" && params.get("code")) {
          if (!clientCreds()) {
            setAuthError("Enter a client id and a client secret.");
            navRef.current("/credentials", { replace: true });
            return;
          }
          const went = await finishCallback(window.location.search, () => cancel, (next) => {
            navRef.current(next, { replace: true });
          });
          if (went && !cancel) setReady(true);
          return;
        }
        if (!clientCreds()) {
          rememberReturn();
          navRef.current("/credentials", { replace: true });
          return;
        }
        if (!accessToken()) {
          await startLogin();
          return;
        }
        if (!cancel) {
          setError(null);
          setReady(true);
        }
      } catch (err) {
        if (cancel) return;
        const message = err instanceof Error ? err.message : "Sign-in failed.";
        if (window.location.pathname === "/credentials") return;
        if (message === "The API document is unavailable." || message.startsWith("openapi:")) {
          setError(message);
          return;
        }
        if (message === "The client id or secret was rejected." || !clientCreds()) {
          setAuthError(message);
          navRef.current("/credentials", { replace: true });
          return;
        }
        setError(message);
      }
    })();
    return () => {
      cancel = true;
    };
  }, [location.pathname, attempt]);

  if (location.pathname === "/credentials") {
    return <CredentialsForm />;
  }
  if (error) {
    return (
      <p className="warn">
        {error}{" "}
        <button
          type="button"
          onClick={() => {
            setError(null);
            setAttempt((n) => n + 1);
          }}
        >
          Retry
        </button>
      </p>
    );
  }
  if (!ready) return <p>Signing in…</p>;
  return <Shell />;
}
