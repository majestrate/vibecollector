const APP_ROUTES = ["/credentials", "/callback", "/reputation", "/talkers", "/traffic", "/globe", "/flows", "/map", "/asn"];

/**
 * pageBase is the directory this page is mounted in.
 * pathname is window.location.pathname.
 * A known shell route is removed from the end. The result has no trailing slash.
 * The site root is an empty string.
 */
export function pageBase(pathname: string): string {
  let path = pathname || "/";
  const q = path.indexOf("?");
  if (q >= 0) path = path.slice(0, q);
  const hash = path.indexOf("#");
  if (hash >= 0) path = path.slice(0, hash);
  if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
  for (const route of APP_ROUTES) {
    if (path === route) return "";
    if (path.endsWith(route)) {
      const prefix = path.slice(0, -route.length);
      if (prefix.startsWith("/") && !prefix.endsWith("/")) return prefix;
    }
  }
  if (path === "" || path === "/") return "";
  return path;
}

/**
 * appPath is pathname with the mount directory removed.
 * /app/flows becomes /flows. A page at the site root is unchanged.
 */
export function appPath(pathname: string): string {
  const base = pageBase(pathname);
  if (base === "") return pathname === "" ? "/" : pathname;
  if (pathname === base || pathname === base + "/") return "/";
  if (pathname.startsWith(base + "/")) return pathname.slice(base.length);
  return pathname;
}

/**
 * rooted joins route onto the directory of the current page.
 * route is an absolute path such as /oauth/token.
 * A page at /app/flows yields /app/oauth/token.
 * With no window, route is returned unchanged.
 */
export function rooted(route: string): string {
  const path = route.startsWith("/") ? route : "/" + route;
  if (typeof window === "undefined") return path;
  const base = pageBase(window.location.pathname || "/");
  return base === "" ? path : base + path;
}
