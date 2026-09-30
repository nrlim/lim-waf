# Firewall-owned CSP

When `security_headers.enabled: true`, LIM-WAF replaces upstream Content-Security-Policy values with one configured policy. Other security headers retain upstream values when present. `sites[].csp` overrides `security_headers.csp`; a missing site policy inherits the global policy (default `default-src 'self'`). The automatic www alias inherits its site's policy. Reload/rebuild handlers after configuration changes.

CSP is app-specific: a universal permissive policy defeats protection. Configure frontend sites individually. Only grant origins used by that site. Do not add unsafe-eval in production. Inline Next.js hydration currently requires unsafe-inline; a nonce cannot be implemented safely by the firewall alone without app integration.

## Wif-Me production example

Merge these fields into the existing server configuration, keeping other sites and security settings intact:

```yaml
security_headers:
  enabled: true
  hsts: true
  hsts_max_age: 31536000
  csp: "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
  frame_options: DENY
  referrer_policy: strict-origin-when-cross-origin

sites:
  - domain: wifme.id
    backend: http://127.0.0.1:3301
    waf:
      enabled: true
      mode: "on"
    csp: >-
      default-src 'self';
      script-src 'self' 'unsafe-inline' https://www.googletagmanager.com;
      style-src 'self' 'unsafe-inline';
      img-src 'self' data: blob: https://*.google-analytics.com https://*.tile.openstreetmap.org https://tile.openstreetmap.org https://*.basemaps.cartocdn.com;
      font-src 'self' data:;
      connect-src 'self' https://*.google-analytics.com https://www.googletagmanager.com https://*.tile.openstreetmap.org https://tile.openstreetmap.org https://*.basemaps.cartocdn.com https://router.project-osrm.org;
      frame-src 'none'; object-src 'none'; worker-src 'self' blob:;
      manifest-src 'self'; frame-ancestors 'none'; base-uri 'self';
      form-action 'self' https://checkout.pymnt.app https://pay.sumopod.com https://sumo.sandbox.pymnt.global https://pay-sandbox.sumopod.com;
      upgrade-insecure-requests
```

This migrates Wif-Me's existing origins, including sandbox payment origins for compatibility; remove sandbox origins only after confirming that environment never uses them. This changes no payment amounts or webhook binding.

Private document endpoints emitting exactly `Content-Security-Policy: sandbox` remain sandboxed: LIM-WAF folds that directive into its single policy. Do not remove this resource-specific protection.

## Rollout

1. Build and deploy the updated LIM-WAF binary first. Configure the explicit Wif-Me site policy; preserve policies/config for other hosts. Do not replace the entire server config with this snippet.
2. Confirm public responses contain exactly one CSP, with no unsafe-eval, on HTML, static JS, API, and denied requests. Check private documents still contain sandbox.
3. Remove competing CSP injection in outer Nginx. The firewall cannot prevent an outer proxy appending headers after the response leaves it.
4. Only then deploy Wif-Me without global CSP. Direct upstream access and deployments without this firewall no longer have document CSP; restrict origin ports to the trusted proxy.
5. Test login/OAuth, uploads/private documents, maps, analytics, SSE initial event/heartbeat, and payment redirect with a new safe UAT order.
6. Rollback: restore app CSP before disabling/removing the firewall policy.

The wrapper commits headers before flush, supporting streaming responses without buffering their bodies. Unknown-host responses have no backend policy and are not used to serve any site's app.
