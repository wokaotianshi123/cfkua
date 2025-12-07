// _worker.js

/**
 * Configuration & Constants
 */
const BAN_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-xss-protection",
  "x-content-type-options",
  "report-to",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy"
]);

const CF_HEADERS_PREFIX = ["cf-", "cdn-loop", "x-forwarded", "x-real-ip"];

/**
 * Main Worker Logic
 */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Root Access: Return Camouflaged UI
    if (url.pathname === "/") {
      return new Response(getLandingPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    // 2. Parse Target URL
    // Format: https://worker.dev/https://target.com/path
    let targetUrlStr = url.pathname.slice(1) + url.search + url.hash;

    // Protocol Fixer
    if (targetUrlStr.startsWith("http") && !/^https?:\/\//.test(targetUrlStr)) {
        targetUrlStr = targetUrlStr.replace(/^(https?):\/+/, "$1://");
    }

    // Handle Relative Paths (Referer based recovery)
    if (!targetUrlStr.startsWith("http")) {
      const referer = request.headers.get("Referer");
      if (referer) {
        try {
          const refUrl = new URL(referer);
          if (refUrl.origin === url.origin) {
            // Extract the real target from the proxy referer
            let refTarget = refUrl.pathname.slice(1) + refUrl.search;
            if (refTarget.startsWith("http") && !/^https?:\/\//.test(refTarget)) {
                refTarget = refTarget.replace(/^(https?):\/+/, "$1://");
            }
            if (refTarget.startsWith("http")) {
                const base = new URL(refTarget);
                targetUrlStr = new URL(targetUrlStr, base.href).href;
            }
          }
        } catch (e) {}
      }
    }

    // 3. Validate Target
    let targetUrl;
    try {
      if (!targetUrlStr.startsWith("http")) throw new Error();
      targetUrl = new URL(targetUrlStr);
    } catch (e) {
      // Fail silently or return generic error to avoid probing
      return new Response("400 Bad Request", { status: 400 });
    }

    // 4. Request Header Masquerade
    const newHeaders = new Headers();
    const isMethods = ["GET", "HEAD", "OPTIONS"].includes(request.method);

    for (const [key, value] of request.headers) {
      const lowerKey = key.toLowerCase();
      // Drop CF specific headers to avoid detection by target
      if (CF_HEADERS_PREFIX.some(prefix => lowerKey.startsWith(prefix))) continue;
      // Drop Cookie/Auth for anonymity (optional: keep if you want login support)
      // if (lowerKey === 'cookie') continue; 
      newHeaders.set(key, value);
    }

    // Standardize User-Agent if missing or suspicious
    if (!newHeaders.get("User-Agent")) {
        newHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
    }

    // Spoof Host & Origin
    newHeaders.set("Host", targetUrl.host);
    if (!isMethods) {
        newHeaders.set("Origin", targetUrl.origin);
        newHeaders.set("Referer", targetUrl.origin); // Neutralize Referer
    }

    // 5. Fetch Execution
    let response;
    try {
      if (request.method === "OPTIONS") {
          return new Response(null, {
              status: 204,
              headers: {
                  "Access-Control-Allow-Origin": "*",
                  "Access-Control-Allow-Methods": "*",
                  "Access-Control-Allow-Headers": "*"
              }
          });
      }

      response = await fetch(targetUrlStr, {
        method: request.method,
        headers: newHeaders,
        body: request.body,
        redirect: "manual" // Handle redirects manually to rewrite them
      });
    } catch (e) {
      return new Response("Gateway Error", { status: 502 });
    }

    // 6. Process Response Headers
    const resHeaders = new Headers(response.headers);
    BAN_HEADERS.forEach(h => resHeaders.delete(h));
    
    // Enable CORS for the proxy wrapper
    resHeaders.set("Access-Control-Allow-Origin", "*");
    resHeaders.set("Access-Control-Allow-Credentials", "true");

    // Rewrite Redirects
    const location = resHeaders.get("Location");
    if (location) {
      try {
        const absoluteLoc = new URL(location, targetUrl.href).href;
        resHeaders.set("Location", url.origin + "/" + absoluteLoc);
      } catch (e) {}
    }

    // 7. Content Processing
    const contentType = resHeaders.get("Content-Type") || "";
    
    // Handler: M3U8 (HLS Streaming)
    if (contentType.includes("mpegurl") || targetUrlStr.endsWith(".m3u8")) {
        const text = await response.text();
        const baseUrl = targetUrlStr.substring(0, targetUrlStr.lastIndexOf("/") + 1);
        const rewritten = text.replace(/^(?!#)(?!\s)(.+)$/gm, (m) => {
            const line = m.trim();
            if (!line) return line;
            try {
                const abs = line.startsWith("http") ? line : new URL(line, baseUrl).href;
                return url.origin + "/" + abs;
            } catch (e) { return line; }
        });
        return new Response(rewritten, {
            status: response.status,
            headers: resHeaders
        });
    }

    // Handler: HTML (The Injector)
    if (contentType.includes("text/html")) {
      return new HTMLRewriter()
        .on("head", new HeadInjector(url.origin, targetUrl.href))
        .on("a", new AttrRewriter("href", url.origin, targetUrl.href))
        .on("img", new AttrRewriter("src", url.origin, targetUrl.href)) // Also handles srcset
        .on("link", new AttrRewriter("href", url.origin, targetUrl.href))
        .on("script", new AttrRewriter("src", url.origin, targetUrl.href))
        .on("form", new AttrRewriter("action", url.origin, targetUrl.href))
        .on("iframe", new AttrRewriter("src", url.origin, targetUrl.href))
        .on("video", new AttrRewriter("src", url.origin, targetUrl.href))
        .on("audio", new AttrRewriter("src", url.origin, targetUrl.href))
        .on("source", new AttrRewriter("src", url.origin, targetUrl.href))
        .on("object", new AttrRewriter("data", url.origin, targetUrl.href))
        // Meta Refresh Fix
        .on("meta", {
            element(e) {
                const httpEquiv = e.getAttribute("http-equiv");
                if (httpEquiv && httpEquiv.toLowerCase() === "refresh") {
                    const content = e.getAttribute("content");
                    if (content) {
                        const m = content.match(/url\s*=\s*['"]?([^'";]+)['"]?/i);
                        if (m && m[1]) {
                            try {
                                const abs = new URL(m[1], targetUrl.href).href;
                                e.setAttribute("content", content.replace(m[1], url.origin + "/" + abs));
                            } catch(err) {}
                        }
                    }
                }
            }
        })
        .transform(response);
    }

    // Passthrough for binary/other types
    return new Response(response.body, {
      status: response.status,
      headers: resHeaders
    });
  }
};

/**
 * HTML Rewriters
 */
class HeadInjector {
    constructor(proxyUrl, realUrl) {
        this.p = proxyUrl;
        this.r = realUrl;
    }
    element(e) {
        // Injected script is minified and uses obscure variable names to prevent regex detection
        const script = `
        <script>
        (function(){
            const C={o:'${this.p}',t:'${this.r}'};
            const w=window,d=document,h=history;
            const u=(s)=> {
                if(!s)return s;
                if(s.startsWith(C.o))return s;
                if(/^(data|blob|javascript):/.test(s))return s;
                try{return C.o+'/'+new URL(s,C.t).href}catch(_){return s}
            };
            // Hook History
            const ps=h.pushState,rs=h.replaceState;
            const hs=(a)=>{if(a.length>=3&&typeof a[2]==='string')a[2]=u(a[2]);return a};
            h.pushState=function(...a){return ps.apply(this,hs(a))};
            h.replaceState=function(...a){return rs.apply(this,hs(a))};
            // Hook Fetch
            const of=w.fetch;
            w.fetch=function(i,n){return of(typeof i==='string'?u(i):i,n)};
            // Hook XHR
            const ox=XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open=function(m,v,...a){return ox.call(this,m,u(v),...a)};
            // Hook Element Attributes (Setter)
            ['src','href','action','data'].forEach(a=>{
                const P=Object.getPrototypeOf(d.createElement(a==='action'?'form':'a'));
                const D=Object.getOwnPropertyDescriptor(P,a==='href'?'href':a);
                if(D&&D.set){
                    Object.defineProperty(P,a,{
                        set:function(v){D.set.call(this,u(v))},
                        get:D.get,enumerable:true,configurable:true
                    });
                }
            });
            // Kill SW
            if(navigator.serviceWorker)navigator.serviceWorker.register=()=>new Promise(()=>{});
        })();
        </script>
        `.replace(/\s+/g, ' '); // Simple minify
        e.prepend(script, { html: true });
    }
}

class AttrRewriter {
  constructor(attr, proxy, base) {
    this.attr = attr;
    this.proxy = proxy;
    this.base = base;
  }
  element(e) {
    const v = e.getAttribute(this.attr);
    if (v && !v.startsWith("data:") && !v.startsWith("javascript:") && !v.startsWith("#")) {
      try {
        e.setAttribute(this.attr, this.proxy + "/" + new URL(v, this.base).href);
      } catch (_) {}
    }
    // Special handling for srcset on images
    if (e.tagName === "img" && e.hasAttribute("srcset")) {
        const src = e.getAttribute("srcset");
        const newSrc = src.split(",").map(p => {
            const [url, desc] = p.trim().split(/\s+/);
            try {
                return this.proxy + "/" + new URL(url, this.base).href + (desc ? " " + desc : "");
            } catch (_) { return p; }
        }).join(", ");
        e.setAttribute("srcset", newSrc);
    }
  }
}

/**
 * UI Generator
 * A minimalistic "Developer Gateway" look to reduce suspicion
 */
function getLandingPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Service Gateway</title>
    <style>
        :root { --bg: #111; --fg: #eee; --acc: #444; }
        body { background: var(--bg); color: var(--fg); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
        .container { width: 100%; max-width: 600px; padding: 20px; text-align: center; }
        h1 { font-weight: 300; letter-spacing: 2px; opacity: 0.8; margin-bottom: 40px; }
        .box { position: relative; display: flex; width: 100%; border-bottom: 2px solid var(--acc); }
        input { width: 100%; background: transparent; border: none; outline: none; color: white; font-size: 18px; padding: 15px 10px; }
        button { background: var(--acc); border: none; color: white; padding: 0 25px; cursor: pointer; font-weight: bold; transition: background 0.2s; }
        button:hover { background: #666; }
        .note { margin-top: 20px; font-size: 12px; color: #555; }
    </style>
</head>
<body>
    <div class="container">
        <h1>GATEWAY</h1>
        <form onsubmit="go(event)">
            <div class="box">
                <input type="text" id="url" placeholder="Enter destination..." autocomplete="off" required>
                <button type="submit">&rarr;</button>
            </div>
        </form>
        <div class="note">Secure Tunneling Protocol v2.1</div>
    </div>
    <script>
        function go(e) {
            e.preventDefault();
            let u = document.getElementById('url').value.trim();
            if(!u) return;
            if(!u.startsWith('http')) u = 'https://' + u;
            // Native redirection to hide logic
            window.location.href = window.location.origin + '/' + u;
        }
    </script>
</body>
</html>`;
}
