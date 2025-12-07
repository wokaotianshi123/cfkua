// _worker.js

/**
 * Cloudflare Workers Proxy
 * 
 * Combined logic from:
 * 1. User provided script (HTMLRewriter, UI, URL parsing)
 * 2. ymyuuu/Cloudflare-Workers-Proxy (Robust CORS handling, Header filtering)
 */

// Headers to strip from the upstream response to ensure security and proxy functionality
const PRESERVE_HEADERS = new Set([
  'content-type',
  'content-length',
  'last-modified',
  'etag',
  'cache-control',
  'expires',
]);

// Headers that interfere with the proxy rendering or security
const UNSAFE_RESPONSE_HEADERS = new Set([
  'content-security-policy',
  'content-security-policy-report-only',
  'x-frame-options',
  'x-xss-protection',
  'x-content-type-options',
  'report-to',
  'nel',
  'access-control-allow-origin',
  'access-control-allow-methods',
  'access-control-allow-headers',
  'access-control-allow-credentials',
  'access-control-max-age',
  'access-control-expose-headers'
]);

// Headers not to send to the upstream server
const UNSAFE_REQUEST_HEADERS = new Set([
  'cookie',
  'host',
  'origin',
  'referer',
  'cf-connecting-ip',
  'cf-ipcountry',
  'cf-ray',
  'cf-visitor',
  'x-forwarded-proto',
  'x-real-ip'
]);

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Root path returns the UI
    if (url.pathname === "/") {
      return new Response(getRootHtml(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    // 2. Parse target URL
    let actualUrlStr = url.pathname.slice(1) + url.search + url.hash;

    // 2.1 Protocol fix (e.g. https:/google.com -> https://google.com)
    if (actualUrlStr.startsWith("http") && !actualUrlStr.startsWith("http://") && !actualUrlStr.startsWith("https://")) {
        actualUrlStr = actualUrlStr.replace(/^(https?):\/+/, "$1://");
    }

    // 2.2 Handle relative paths (via Referer)
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

    // Validate URL
    if (!actualUrlStr.startsWith("http")) {
       // If mostly invalid, try adding https:// if it looks like a domain
       if (actualUrlStr.indexOf('.') > -1 && actualUrlStr.indexOf('/') === -1) {
           actualUrlStr = 'https://' + actualUrlStr;
       } else {
           return new Response("Invalid URL: " + actualUrlStr, { status: 400 });
       }
    }

    let targetUrl;
    try {
      targetUrl = new URL(actualUrlStr);
    } catch (e) {
      return new Response("Invalid URL Parse Error: " + actualUrlStr, { status: 400 });
    }

    // 3. Handle OPTIONS (CORS Preflight)
    // Always return permissive CORS headers for OPTIONS requests
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 200,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD",
          "Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers") || "*",
          "Access-Control-Allow-Credentials": "true",
          "Access-Control-Max-Age": "86400"
        }
      });
    }

    // 4. Construct Upstream Request
    const newHeaders = new Headers();
    
    // Copy allowlisted headers
    for (const [key, value] of request.headers) {
      const lowerKey = key.toLowerCase();
      if (!UNSAFE_REQUEST_HEADERS.has(lowerKey) && !lowerKey.startsWith('cf-')) {
        newHeaders.set(key, value);
      }
    }

    // Set essential headers for spoofing
    newHeaders.set("Host", targetUrl.host);
    newHeaders.set("User-Agent", request.headers.get("User-Agent") || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36");
    
    // Origin handling: If sending data, set Origin to target, otherwise omit or ensure valid
    if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method)) {
        newHeaders.set("Origin", targetUrl.origin);
    }
    
    // Referer handling
    const clientReferer = request.headers.get("Referer");
    if (clientReferer && clientReferer.startsWith(url.origin)) {
        const realRefererPart = clientReferer.slice(url.origin.length + 1);
        // Clean up the extracted referer
        let fixedReferer = realRefererPart;
        if (fixedReferer.startsWith("http") && !fixedReferer.startsWith("http://") && !fixedReferer.startsWith("https://")) {
            fixedReferer = fixedReferer.replace(/^(https?):\/+/, "$1://");
        }
        if (fixedReferer.startsWith("http")) {
             newHeaders.set("Referer", fixedReferer);
        }
    } else {
        newHeaders.set("Referer", targetUrl.href);
    }

    // 5. Fetch from Upstream
    let response;
    try {
      response = await fetch(actualUrlStr, {
        method: request.method,
        headers: newHeaders,
        body: request.body,
        redirect: "manual" // We handle redirects manually to rewrite Location
      });
    } catch (e) {
      return new Response("Proxy Fetch Error: " + e.message, { status: 502 });
    }

    // 6. Process Response Headers
    const responseHeaders = new Headers();
    
    // Copy upstream headers while filtering unsafe ones
    for (const [key, value] of response.headers) {
        const lowerKey = key.toLowerCase();
        if (!UNSAFE_RESPONSE_HEADERS.has(lowerKey)) {
            responseHeaders.set(key, value);
        }
    }

    // Enforce CORS on Response
    responseHeaders.set("Access-Control-Allow-Origin", "*");
    responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD");
    responseHeaders.set("Access-Control-Allow-Credentials", "true");
    // Ensure all requested headers are allowed in the response
    const reqHeaders = request.headers.get("Access-Control-Request-Headers");
    if (reqHeaders) {
        responseHeaders.set("Access-Control-Allow-Headers", reqHeaders);
    } else {
        responseHeaders.set("Access-Control-Allow-Headers", "*");
    }
    responseHeaders.set("Access-Control-Expose-Headers", "*");

    // Rewrite Location header for redirects
    const location = response.headers.get("Location");
    if (location) {
      try {
        // Resolve relative redirects against the target URL
        const absoluteLocation = new URL(location, targetUrl.href).href;
        responseHeaders.set("Location", url.origin + "/" + absoluteLocation);
      } catch (e) {
        // Fallback if URL resolution fails
        responseHeaders.set("Location", location);
      }
    }

    const contentType = responseHeaders.get("Content-Type") || "";
    const status = response.status;

    // 7. Content Rewriting
    
    // A. M3U8 Playlist
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
            status: status,
            statusText: response.statusText,
            headers: responseHeaders
        });
    }

    // B. HTML Content
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
                    if (typeof u !== 'string') return u;
                    if (u.startsWith(PROXY_ORIGIN)) return u;
                    if (u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('javascript:')) return u;
                    try {
                        const absolute = new URL(u, REAL_BASE_URL).href;
                        return PROXY_ORIGIN + '/' + absolute;
                    } catch(e) {
                        return u;
                    }
                }

                // 1. History API Hook
                const oldPushState = history.pushState;
                const oldReplaceState = history.replaceState;
                
                function wrapHistoryArgs(args) {
                    if (args.length >= 3 && typeof args[2] === 'string') {
                        args[2] = wrapUrl(args[2]);
                    }
                    return args;
                }

                history.pushState = function(...args) {
                    return oldPushState.apply(this, wrapHistoryArgs(args));
                };
                history.replaceState = function(...args) {
                    return oldReplaceState.apply(this, wrapHistoryArgs(args));
                };

                // 2. Element Attribute Hook
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
                            set: function(val) {
                                originalSet.call(this, wrapUrl(val));
                            },
                            get: descriptor.get,
                            enumerable: true,
                            configurable: true
                        });
                    }
                });

                // 3. Fetch Hook
                const oldFetch = window.fetch;
                window.fetch = function(input, init) {
                    let url = input;
                    if (typeof input === 'string') {
                        url = wrapUrl(input);
                    } else if (input instanceof Request) {
                        // Cloning request with new URL is tricky, usually easier to just modify string url
                        url = wrapUrl(input.url);
                    }
                    return oldFetch(url, init);
                };

                // 4. XHR Hook
                const oldOpen = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(method, url, ...args) {
                    return oldOpen.call(this, method, wrapUrl(url), ...args);
                };

                // 5. Disable ServiceWorker to prevent bypass
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
                             const originalUrl = match[1];
                             try {
                                 const absoluteUrl = new URL(originalUrl, targetUrl.href).href;
                                 const newUrl = url.origin + "/" + absoluteUrl;
                                 const newContent = content.replace(originalUrl, newUrl);
                                 element.setAttribute("content", newContent);
                             } catch(e) {}
                        }
                    }
                }
            }
        });

      return rewriter.transform(new Response(response.body, {
        status: status,
        statusText: response.statusText,
        headers: responseHeaders
      }));
    }

    // C. Binary / Other Content (just stream it)
    return new Response(response.body, {
      status: status,
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
    // Handle data-src commonly used in lazy loading
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
<html lang="zh-CN">
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
