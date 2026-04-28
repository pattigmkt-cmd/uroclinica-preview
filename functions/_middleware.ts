/**
 * Cloudflare Pages Functions — middleware global del sitio.
 *
 * Firewall por código en el edge. Aplica a TODA request antes de servir
 * el asset estático.
 *
 * Filtros (gratis, sin Pro tier):
 *  - País (ISO-3166): RU, CN, KP, IR, BY → 403
 *  - Métodos: solo GET, POST, HEAD, OPTIONS → 405 en otros
 *  - User-Agents de scrapers/curl/wget/scanners → 403
 *  - POSTs > 100KB → 413 (anti-spam de form)
 */

const BLOCKED_COUNTRIES = new Set(["RU", "CN", "KP", "IR", "BY"]);
const ALLOWED_METHODS = new Set(["GET", "POST", "HEAD", "OPTIONS"]);
const BAD_UA_RE =
  /(curl\/|wget\/|python-requests\/|scrapy\/|httpie\/|libwww-perl|java\/|go-http-client|nikto|sqlmap|nessus|acunetix|nmap|masscan|zgrab)/i;
const MAX_BODY_BYTES = 100 * 1024;

interface CfContext {
  request: Request;
  next: () => Promise<Response>;
}

export const onRequest = async (ctx: CfContext): Promise<Response> => {
  const { request, next } = ctx;

  if (!ALLOWED_METHODS.has(request.method)) {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const country = (request as { cf?: { country?: string } }).cf?.country;
  if (country && BLOCKED_COUNTRIES.has(country)) {
    return new Response("Forbidden", { status: 403 });
  }

  const ua = request.headers.get("user-agent") ?? "";
  if (!ua || BAD_UA_RE.test(ua)) {
    return new Response("Forbidden", { status: 403 });
  }

  if (request.method === "POST") {
    const cl = request.headers.get("content-length");
    if (cl && Number.parseInt(cl, 10) > MAX_BODY_BYTES) {
      return new Response("Payload Too Large", { status: 413 });
    }
  }

  return next();
};
