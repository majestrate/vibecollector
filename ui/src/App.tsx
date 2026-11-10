import { useEffect, useRef, useState, type ReactElement } from "react";
import { useNavigate } from "react-router-dom";
import { prefixFromSpec } from "./api";
import { finishCallback, startLogin } from "./auth";
import { accessToken, setAPIPrefix } from "./session";
import { Shell } from "./shell";

/**
 * App loads the OpenAPI prefix and signs the shell in.
 * The access token stays in memory. A failed exchange shows Sign in again.
 */
export function App(): ReactElement {
  const nav = useNavigate();
  const navRef = useRef(nav);
  navRef.current = nav;
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // A new navigate identity must not rerun this effect. The cleaned-up run
  // would delete the stored return path before the live run can read it.
  useEffect(() => {
    let cancel = false;
    (async () => {
      try {
        const res = await fetch("/openapi.json", { headers: { Accept: "application/json" } });
        if (cancel) return;
        if (!res.ok) throw new Error("The API document is unavailable.");
        const spec: unknown = await res.json();
        if (cancel) return;
        setAPIPrefix(prefixFromSpec(spec));
        const params = new URLSearchParams(window.location.search);
        if (window.location.pathname === "/callback" && params.get("code")) {
          const went = await finishCallback(window.location.search, () => cancel, (path) => {
            navRef.current(path, { replace: true });
          });
          if (went && !cancel) setReady(true);
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
  }, []);

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
