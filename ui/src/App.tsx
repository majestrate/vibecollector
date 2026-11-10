import { useEffect, useState, type ReactElement } from "react";
import { useNavigate } from "react-router-dom";
import { prefixFromSpec } from "./api";
import { consumeReturn, finishLogin, startLogin } from "./auth";
import { accessToken, setAPIPrefix } from "./session";
import { Shell } from "./shell";

/**
 * App loads the OpenAPI prefix and signs the shell in.
 * The access token stays in memory. A failed exchange shows Sign in again.
 */
export function App(): ReactElement {
  const nav = useNavigate();
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancel = false;
    (async () => {
      try {
        const res = await fetch("/openapi.json", { headers: { Accept: "application/json" } });
        if (!res.ok) throw new Error("The API document is unavailable.");
        const spec: unknown = await res.json();
        setAPIPrefix(prefixFromSpec(spec));
        const params = new URLSearchParams(window.location.search);
        if (window.location.pathname === "/callback" && params.get("code")) {
          await finishLogin(window.location.search);
          const ret = consumeReturn();
          if (cancel) return;
          nav(ret, { replace: true });
          setReady(true);
          return;
        }
        if (!accessToken()) {
          await startLogin();
          return;
        }
        if (!cancel) setReady(true);
      } catch (err) {
        if (!cancel) setError(err instanceof Error ? err.message : "Sign-in failed.");
      }
    })();
    return () => {
      cancel = true;
    };
  }, [nav]);

  if (error) {
    return (
      <p className="warn">
        {error}{" "}
        <button
          type="button"
          onClick={() => {
            setError(null);
            void startLogin().catch((err: unknown) => {
              setError(err instanceof Error ? err.message : "Sign-in failed.");
            });
          }}
        >
          Sign in
        </button>
      </p>
    );
  }
  if (!ready) return <p>Signing in…</p>;
  return <Shell />;
}
