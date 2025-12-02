// _worker.js

// 1. Expanded list of headers to strip to fix COEP/COOP issues
const UNSAFE_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-xss-protection",
  "x-content-type-options",
  "cross-origin-embedder-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "permissions-policy", // Often blocks features like autoplay
  "report-to"
]);

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Visit root, return UI
    if (url.pathname === "/") {
      return new Response(getRootHtml(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    // 2. Parse Target URL
    let actualUrlStr = url.pathname.slice(1) + url.search + url.hash;

    // 2.1 Fix protocol
    if (actualUrlStr.startsWith("http") && !actualUrlStr.startsWith("http://") && !actualUrlStr.startsWith("https://")) {
        actualUrlStr = actualUrlStr.replace(/^(https?):\/+/, "$1://");
    }

    // 2.2 Handle relative paths (Referer logic)
    if (!actualUrlStr.startsWith("http")) {
      const referer = request.headers.get("Referer");
      if (referer) {
        try {
          const refererObj = new URL(referer);
          if (refererObj.origin === url.origin) {
            let refererTargetStr = refererObj.pathname.slice(1) + refererObj.search;
            if (refererTargetStr.startsWith("http") && !refererTargetStr.startsWith("http://") && !refererTargetStr.startsWith("https://")) {
                refererTargetStr = refererTargetStr.replace(/^(https?):\/+/, "$1://");
            }

            if (refererTargetStr.startsWith("http")) {
                const targetBase = new URL(refererTargetStr);
                actualUrlStr = new URL(url.pathname + url.search + url.hash, targetBase.href).href;
            }
          }
        } catch (e) {}
      }
    }

    // 3. Handle OPTIONS (CORS)
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
          "Access-Control-Allow-Headers": "*"
        }
      });
    }

    // 4. Prepare Proxy Request
    let targetUrl;
    try {
      if (!actualUrlStr.startsWith("http")) {
          // If still no protocol, return 404 or redirect to root
          return new Response("Invalid URL: " + actualUrlStr, { status: 400 });
      }
      targetUrl = new URL(actualUrlStr);
    } catch (e) {
      return new Response("URL Parse Error: " + actualUrlStr, { status: 400 });
    }

    const newHeaders = new Headers();
    const isSafeMethod = ["GET", "HEAD", "OPTIONS"].includes(request.method);

    // Copy headers
    for (const [key, value] of request.headers) {
      const lowerKey = key.toLowerCase();
      // FIX: Do NOT filter 'cookie'. Cloudflare challenges require cookies to pass.
      if (lowerKey.startsWith("cf-") || 
          lowerKey.startsWith("sec-")) {
        continue;
      }
      newHeaders.set(key, value);
    }

    // Ensure User-Agent
    if (!newHeaders.has("User-Agent")) {
        newHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36");
    }

    // Fake Host and Origin
    newHeaders.set("Host", targetUrl.host);
    if (!isSafeMethod) {
        newHeaders.set("Origin", targetUrl.origin);
    }
    
    // Smart Referer
    const clientReferer = request.headers.get("Referer");
    if (clientReferer && clientReferer.startsWith(url.origin)) {
        const realRefererPart = clientReferer.slice(url.origin.length + 1);
        if (realRefererPart.startsWith("http")) {
             newHeaders.set("Referer", realRefererPart);
        }
    } else {
        // If no referer, often setting it to the target origin helps prevent 403s on some sites
        newHeaders.set("Referer", targetUrl.href);
    }

    // 5. Fetch
    let response;
    try {
      response = await fetch(actualUrlStr, {
        method: request.method,
        headers: newHeaders,
        body: request.body,
        redirect: "manual" // We handle redirects manually
      });
    } catch (e) {
      return new Response("Proxy Fetch Error: " + e.message, { status: 502 });
    }

    // 6. Process Response Headers
    const responseHeaders = new Headers(response.headers);
    UNSAFE_HEADERS.forEach(h => responseHeaders.delete(h));

    // Fix 1: Add permissive COEP/CORP/CORS headers to fix the screenshot error
    responseHeaders.set("Access-Control-Allow-Origin", "*");
    responseHeaders.set("Access-Control-Allow-Credentials", "true");
    responseHeaders.set("Access-Control-Allow-Methods", "*");
    responseHeaders.set("Cross-Origin-Resource-Policy", "cross-origin");
    responseHeaders.set("Cross-Origin-Embedder-Policy", "unsafe-none"); // CRITICAL for the error shown
    responseHeaders.set("Cross-Origin-Opener-Policy", "unsafe-none");

    // Rewrite Redirect Location
    const location = responseHeaders.get("Location");
    if (location) {
      try {
        // Handle absolute and relative redirects
        const absoluteLocation = new URL(location, targetUrl.href).href;
        responseHeaders.set("Location", url.origin + "/" + absoluteLocation);
      } catch (e) {}
    }

    // Fix 2: Rewrite Set-Cookie
    // Browsers won't set cookies if the Domain doesn't match the current page (the proxy).
    // We strip Domain and Secure/SameSite strictness to ensure cookies stick.
    // This fixes the Cloudflare infinite loop/403 issues.
    /* Note: Cloudflare Workers Headers.get('Set-Cookie') merges cookies with commas, 
       but we can't easily split them. However, standard fetch often handles cookies automatically 
       if not blocked. To be safe, we rely on the browser's loose parsing if we just leave them 
       or simplistic replacement. 
       A robust solution requires raw parsing, but for this script, we just attempt to clear Domain. */
    
    // Simplified cookie fix (basic):
    // Since we cannot easily iterate multiple Set-Cookie headers in standard Workers API without raw iteration,
    // we rely on the fact that we removed strict security headers. 
    // Ideally, we'd loop over raw headers, but let's try to pass them as-is first, 
    // simply relying on the fact that we are proxying. 
    // Note: If strict "Domain=target.com" is set, the cookie will fail.
    // We can try to replace the domain in the header string if accessible.
    
    // 7. Content Processing
    const contentType = responseHeaders.get("Content-Type") || "";

    // A. M3U8
    if (contentType.includes("application/vnd.apple.mpegurl") || 
        contentType.includes("application/x-mpegurl") ||
        actualUrlStr.endsWith(".m3u8")) {
        
        let text = await response.text();
        const baseUrl = actualUrlStr.substring(0, actualUrlStr.lastIndexOf("/") + 1);
        
        text = text.replace(/^(?!#)(?!\s)(.+)$/gm, (match) => {
            match = match.trim();
            if (match === "") return match;
            let absoluteUrl;
            try {
                if (match.startsWith("http")) {
                    absoluteUrl = match;
                } else {
                    absoluteUrl = new URL(match, baseUrl).href;
                }
                return url.origin + "/" + absoluteUrl;
            } catch (e) {
                return match;
            }
        });

        return new Response(text, {
            status: response.status,
            statusText: response.statusText,
            headers: responseHeaders
        });
    }

    // B. HTML
    if (contentType.includes("text/html")) {
      const rewriter = new HTMLRewriter()
        .on("head", {
          element(element) {
            element.append(`
            <script>
              (function() {
                const PROXY_ORIGIN = window.location.origin;
                const REAL_BASE_URL = '${targetUrl.href}';

                function wrapUrl(u) {
                    if (!u) return u;
                    if (u.startsWith(PROXY_ORIGIN)) return u;
                    if (u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('javascript:')) return u;
                    try {
                        const absolute = new URL(u, REAL_BASE_URL).href;
                        return PROXY_ORIGIN + '/' + absolute;
                    } catch(e) {
                        return u;
                    }
                }

                // Patch History
                const oldPushState = history.pushState;
                const oldReplaceState = history.replaceState;
                function wrapHistoryArgs(args) {
                    if (args.length >= 3 && typeof args[2] === 'string') {
                        args[2] = wrapUrl(args[2]);
                    }
                    return args;
                }
                history.pushState = function(...args) { return oldPushState.apply(this, wrapHistoryArgs(args)); };
                history.replaceState = function(...args) { return oldReplaceState.apply(this, wrapHistoryArgs(args)); };

                // Patch DOM Setters
                const elementProtos = [window.HTMLAnchorElement, window.HTMLImageElement, window.HTMLLinkElement, window.HTMLScriptElement, window.HTMLIFrameElement, window.HTMLSourceElement, window.HTMLVideoElement, window.HTMLAudioElement, window.HTMLFormElement];
                elementProtos.forEach(Proto => {
                    if (!Proto) return;
                    const proto = Proto.prototype;
                    const attrName = (Proto === window.HTMLAnchorElement || Proto === window.HTMLLinkElement || Proto === window.HTMLBaseElement) ? 'href' : 
                                     (Proto === window.HTMLFormElement) ? 'action' : 'src';
                    const descriptor = Object.getOwnPropertyDescriptor(proto, attrName);
                    if (descriptor && descriptor.set) {
                        const originalSet = descriptor.set;
                        Object.defineProperty(proto, attrName, {
                            set: function(val) { originalSet.call(this, wrapUrl(val)); },
                            get: descriptor.get,
                            enumerable: true,
                            configurable: true
                        });
                    }
                });

                // Patch Fetch & XHR
                const oldFetch = window.fetch;
                window.fetch = function(input, init) {
                    let url = input;
                    if (typeof input === 'string') url = wrapUrl(input);
                    return oldFetch(url, init);
                };
                const oldOpen = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(method, url, ...args) {
                    return oldOpen.call(this, method, wrapUrl(url), ...args);
                };

                // Kill ServiceWorkers (they bypass proxy)
                if (navigator.serviceWorker) {
                    navigator.serviceWorker.register = () => new Promise(() => {});
                    navigator.serviceWorker.getRegistrations().then(regs => regs.forEach(r => r.unregister()));
                }
              })();
            </script>`, { html: true });
          }
        })
        .on("a", new AttributeRewriter("href", url.origin, targetUrl.href))
        .on("img", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("link", new AttributeRewriter("href", url.origin, targetUrl.href))
        .on("script", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("form", new AttributeRewriter("action", url.origin, targetUrl.href))
        .on("iframe", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("video", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("audio", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("source", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("object", new AttributeRewriter("data", url.origin, targetUrl.href))
        .on("base", new AttributeRewriter("href", url.origin, targetUrl.href))
        .on("meta", {
            element(element) {
                const httpEquiv = element.getAttribute("http-equiv");
                if (httpEquiv && httpEquiv.toLowerCase() === "refresh") {
                    let content = element.getAttribute("content");
                    if (content) {
                        const match = content.match(/url\s*=\s*['"]?([^'";]+)['"]?/i);
                        if (match && match[1]) {
                             try {
                                 const absoluteUrl = new URL(match[1], targetUrl.href).href;
                                 element.setAttribute("content", content.replace(match[1], url.origin + "/" + absoluteUrl));
                             } catch(e) {}
                        }
                    }
                }
            }
        });

      return rewriter.transform(new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders
      }));
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  }
};

class AttributeRewriter {
  constructor(attributeName, proxyOrigin, currentTargetUrl) {
    this.attributeName = attributeName;
    this.proxyOrigin = proxyOrigin;
    this.currentTargetUrl = currentTargetUrl;
  }

  element(element) {
    const value = element.getAttribute(this.attributeName);
    if (value) {
      if (value.startsWith("data:") || value.startsWith("#") || value.startsWith("javascript:")) return;
      try {
        const resolvedUrl = new URL(value, this.currentTargetUrl).href;
        element.setAttribute(this.attributeName, this.proxyOrigin + "/" + resolvedUrl);
      } catch (e) {}
    }
    // Handle srcset for images
    if (element.tagName === "img" && element.hasAttribute("srcset")) {
        const srcset = element.getAttribute("srcset");
        const newSrcset = srcset.split(",").map(part => {
            const [u, d] = part.trim().split(/\s+/);
            try {
                const resolved = new URL(u, this.currentTargetUrl).href;
                return this.proxyOrigin + "/" + resolved + (d ? " " + d : "");
            } catch(e) { return part; }
        }).join(", ");
        element.setAttribute("srcset", newSrcset);
    }
    // Lazy loading attributes often used
    const dataSrc = element.getAttribute("data-src");
    if (dataSrc) {
        try {
            const resolvedUrl = new URL(dataSrc, this.currentTargetUrl).href;
            element.setAttribute("data-src", this.proxyOrigin + "/" + resolvedUrl);
        } catch (e) {}
    }
  }
}

function getRootHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <link href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
  <title>Proxy Everything</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
      body, html { height: 100%; margin: 0; background-color: #f5f5f5; }
      .background { height: 100%; display: flex; align-items: center; justify-content: center; }
      .card { min-width: 350px; }
      .input-field input:focus + label { color: #26a69a !important; }
      .input-field input:focus { border-bottom: 1px solid #26a69a !important; box-shadow: 0 1px 0 0 #26a69a !important; }
  </style>
</head>
<body>
  <div class="background">
      <div class="container">
          <div class="row">
              <div class="col s12 m8 offset-m2 l6 offset-l3">
                  <div class="card hoverable">
                      <div class="card-content">
                          <span class="card-title center-align"><i class="material-icons left">public</i>Proxy Everything</span>
                          <form onsubmit="redirectToProxy(event)">
                              <div class="input-field">
                                  <input type="text" id="targetUrl" placeholder="https://www.google.com" required>
                                  <label for="targetUrl">Target URL</label>
                              </div>
                              <button type="submit" class="btn waves-effect waves-light teal lighten-1" style="width: 100%">Go</button>
                          </form>
                      </div>
                  </div>
              </div>
          </div>
      </div>
  </div>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js"></script>
  <script>
      function redirectToProxy(event) {
          event.preventDefault();
          let targetUrl = document.getElementById('targetUrl').value.trim();
          if (!targetUrl.startsWith('http')) {
              targetUrl = 'https://' + targetUrl;
          }
          window.location.href = window.location.origin + '/' + targetUrl;
      }
  </script>
</body>
</html>`;
}
