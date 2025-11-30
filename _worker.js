
// _worker.js

// 1. 想要移除的响应头 (解决 CSP, Frame 限制等问题)
const UNSAFE_RESPONSE_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-xss-protection",
  "x-content-type-options"
]);

// 2. 想要移除的请求头 (隐身模式，防止暴露代理 IP)
const UNSAFE_REQUEST_HEADERS = new Set([
  "x-forwarded-for",
  "x-real-ip",
  "via",
  "cf-connecting-ip",
  "cf-worker",
  "forwarded"
]);

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. 访问根目录，返回 UI
    if (url.pathname === "/") {
      return new Response(getRootHtml(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    // 2. 解析目标 URL
    let actualUrlStr = url.pathname.slice(1) + url.search + url.hash;

    // --- 核心修复：Service Worker 拦截 ---
    if (actualUrlStr.includes("service-worker") || actualUrlStr.includes("sw.js") || actualUrlStr.includes("worker.js")) {
        return new Response("/* Proxy: Service Worker Disabled */ self.addEventListener('install', () => self.skipWaiting());", {
            headers: { "Content-Type": "application/javascript" }
        });
    }

    // --- 核心修复：URL 清洗 (解决 zh/https:// 问题) ---
    // 智能提取真实 URL，忽略前面的重定向残余
    // 逻辑：找到字符串中第一个 "http(s)://" 及其之后的所有内容作为目标
    const greedyMatch = actualUrlStr.match(/(https?:\/\/.+)/);
    if (greedyMatch) {
        actualUrlStr = greedyMatch[1];
    }

    // 2.1 修正无协议 URL (处理 /static/css/style.css 404)
    if (!actualUrlStr.startsWith("http")) {
       let fixed = false;
       
       // 策略 A: 尝试通过 Referer 还原
       const referer = request.headers.get("Referer");
       if (referer) {
         try {
           const refererObj = new URL(referer);
           if (refererObj.origin === url.origin) {
             const refererTarget = refererObj.pathname.slice(1);
             const refMatch = refererTarget.match(/(https?:\/\/.+)/);
             if (refMatch) {
                const baseStr = refMatch[1];
                const targetBase = new URL(baseStr);
                actualUrlStr = new URL(actualUrlStr, targetBase.href).href;
                fixed = true;
             }
           }
         } catch(e) {}
       }
       
       // 策略 B: 尝试通过 Cookie 还原 (JSON 404 修复神器)
       if (!fixed) {
           const cookies = request.headers.get("Cookie") || "";
           const targetCookie = cookies.match(/__proxy_target__=([^;]+)/);
           if (targetCookie) {
               try {
                   const baseOrigin = decodeURIComponent(targetCookie[1]);
                   const baseObj = new URL(baseOrigin);
                   actualUrlStr = new URL(actualUrlStr, baseObj.href).href;
                   fixed = true;
               } catch(e) {}
           }
       }

       // 策略 C: 兜底处理
       if (!fixed) {
           // 如果看起来像域名，加 https
           if (actualUrlStr.includes(".") && !actualUrlStr.startsWith("/")) {
               actualUrlStr = "https://" + actualUrlStr;
           } else {
               // 无法解析，返回 404
               return new Response(`Cannot resolve URL: ${actualUrlStr}`, { status: 404 });
           }
       }
    }

    // 3. 处理 OPTIONS 预检请求
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
          "Access-Control-Allow-Headers": "*",
          "Access-Control-Allow-Credentials": "true"
        }
      });
    }

    // 4. 准备代理请求
    let targetUrl;
    try {
      targetUrl = new URL(actualUrlStr);
    } catch (e) {
      return new Response("URL Parse Error: " + e.message, { status: 400 });
    }

    const newHeaders = new Headers();
    for (const [key, value] of request.headers) {
      if (key.startsWith("cf-") || UNSAFE_REQUEST_HEADERS.has(key.toLowerCase())) continue;
      newHeaders.set(key, value);
    }

    newHeaders.set("Host", targetUrl.host);
    // 绕过 Origin 检查 (关键：视频流往往检查这个)
    if (["GET", "HEAD"].includes(request.method)) {
        newHeaders.delete("Origin");
    } else {
        newHeaders.set("Origin", targetUrl.origin);
    }
    newHeaders.set("User-Agent", request.headers.get("User-Agent") || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

    // 智能 Referer
    let newReferer = targetUrl.origin + "/";
    const clientReferer = request.headers.get("Referer");
    if (clientReferer && clientReferer.startsWith(url.origin)) {
        const realRefererPart = clientReferer.slice(url.origin.length + 1);
        const refMatch = realRefererPart.match(/(https?:\/\/.+)/);
        if (refMatch) {
             newReferer = refMatch[1];
        }
    }
    newHeaders.set("Referer", newReferer);

    // 5. 发起请求
    let response;
    try {
      response = await fetch(actualUrlStr, {
        method: request.method,
        headers: newHeaders,
        body: request.body,
        redirect: "manual"
      });
    } catch (e) {
      return new Response("Proxy Fetch Error: " + e.message, { status: 502 });
    }

    // 6. 处理响应头
    const responseHeaders = new Headers(response.headers);
    UNSAFE_RESPONSE_HEADERS.forEach(h => responseHeaders.delete(h));

    responseHeaders.set("Access-Control-Allow-Origin", "*");
    responseHeaders.set("Access-Control-Allow-Credentials", "true");
    responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");

    const contentType = responseHeaders.get("Content-Type") || "";
    if (contentType.includes("text/html")) {
        // 种下目标域名 Cookie
        responseHeaders.append("Set-Cookie", `__proxy_target__=${encodeURIComponent(targetUrl.origin)}; Path=/; SameSite=None; Secure; HttpOnly`);
    }

    // Cookie 清洗
    if (typeof responseHeaders.getSetCookie === 'function') {
         const cookies = responseHeaders.getSetCookie();
         responseHeaders.delete("Set-Cookie");
         cookies.forEach(c => {
             let cleanCookie = c.replace(/Domain=[^;]+;?/gi, "").replace(/Path=[^;]+;?/gi, "");
             cleanCookie += "; Path=/; SameSite=None; Secure";
             responseHeaders.append("Set-Cookie", cleanCookie);
         });
    } else {
        const setCookie = responseHeaders.get("Set-Cookie");
        if (setCookie) {
            const newCookie = setCookie.replace(/Domain=[^;]+;?/gi, "").replace(/Path=[^;]+;?/gi, "") + "; Path=/; SameSite=None; Secure";
            responseHeaders.set("Set-Cookie", newCookie);
        }
    }

    // Location 重写
    const location = responseHeaders.get("Location");
    if (location) {
      try {
        const absoluteLocation = new URL(location, targetUrl.href).href;
        responseHeaders.set("Location", url.origin + "/" + absoluteLocation);
      } catch (e) {}
    }

    // 7. 内容重写
    // A. M3U8
    if (contentType.includes("mpegurl") || actualUrlStr.endsWith(".m3u8")) {
        let text = await response.text();
        const baseUrl = actualUrlStr.substring(0, actualUrlStr.lastIndexOf("/") + 1);
        text = text.replace(/^(?!#)(?!\s)(.+)$/gm, (match) => {
            match = match.trim();
            if (!match) return match;
            try {
                const absUrl = match.startsWith("http") ? match : new URL(match, baseUrl).href;
                return url.origin + "/" + absUrl;
            } catch (e) { return match; }
        });
        return new Response(text, { status: response.status, headers: responseHeaders });
    }

    // B. HTML
    if (contentType.includes("text/html")) {
      const rewriter = new HTMLRewriter()
        .on("head", {
          element(element) {
            element.append(`
            <script>
              (function() {
                const PROXY = window.location.origin;
                const BASE = '${targetUrl.href}'; 
                
                function wrap(u) {
                    if (!u) return u;
                    if (typeof u !== 'string') return u;
                    if (u.includes(PROXY)) return u;
                    if (u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('javascript:') || u.startsWith('#')) return u;
                    
                    u = u.trim();
                    if (u.startsWith('//')) return PROXY + '/https:' + u;
                    if (u.startsWith('/')) {
                        try { return PROXY + '/' + new URL(u, BASE).origin + u; }
                        catch(e) { return PROXY + '/https://' + u; }
                    }
                    if (u.startsWith('http')) return PROXY + '/' + u;
                    try { return PROXY + '/' + new URL(u, BASE).href; } catch (e) { return u; }
                }
                
                // 1. 拦截 Request 构造函数 (关键：解决 fetch(new Request(...)) 导致的泄露)
                const _Request = window.Request;
                window.Request = function(input, init) {
                    let wrappedInput = input;
                    if (typeof input === 'string') {
                        wrappedInput = wrap(input);
                    } else if (input instanceof _Request) {
                        if (!input.url.includes(PROXY)) {
                            wrappedInput = new _Request(wrap(input.url), input);
                        }
                    } else if (input instanceof URL) {
                        wrappedInput = wrap(input.href);
                    }
                    return new _Request(wrappedInput, init);
                };
                window.Request.prototype = _Request.prototype;

                // 2. 拦截 fetch (双重保险)
                const _fetch = window.fetch;
                window.fetch = function(input, init) {
                    let wrappedInput = input;
                    if (typeof input === 'string') {
                        wrappedInput = wrap(input);
                    } else if (input instanceof _Request) {
                        if (!input.url.includes(PROXY)) {
                             wrappedInput = new _Request(wrap(input.url), input);
                        }
                    } else if (input instanceof URL) {
                        wrappedInput = wrap(input.href);
                    }
                    return _fetch(wrappedInput, init);
                };
                
                // 3. 拦截 XHR
                const _open = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(m, u, ...a) {
                    return _open.call(this, m, wrap(u), ...a);
                };

                // 4. 拦截 setAttribute (解决动态 CSS/JS)
                const _setAttribute = Element.prototype.setAttribute;
                Element.prototype.setAttribute = function(name, value) {
                    if (['src', 'href', 'action', 'data', 'poster'].includes(name.toLowerCase())) {
                        return _setAttribute.call(this, name, wrap(value));
                    }
                    return _setAttribute.call(this, name, value);
                };

                // 5. 禁用 Service Worker
                if (navigator.serviceWorker) {
                     navigator.serviceWorker.register = () => new Promise(() => {});
                     navigator.serviceWorker.getRegistrations().then(rs => rs.forEach(r => r.unregister()));
                }

                // 6. 属性劫持 (img.src = ...)
                const tags = {
                    'img': 'src', 'script': 'src', 'link': 'href', 'a': 'href',
                    'iframe': 'src', 'video': 'src', 'audio': 'src', 'source': 'src', 'form': 'action',
                    'object': 'data'
                };
                for (const [tag, attr] of Object.entries(tags)) {
                    const elProto = window[tag.toUpperCase() + 'Element'] || window['HTML' + tag.charAt(0).toUpperCase() + tag.slice(1) + 'Element'];
                    if (!elProto) continue;
                    const desc = Object.getOwnPropertyDescriptor(elProto.prototype, attr);
                    if (desc && desc.set) {
                        Object.defineProperty(elProto.prototype, attr, {
                            set: function(v) { 
                                if(v) { desc.set.call(this, wrap(v)); } 
                                else { desc.set.call(this, v); }
                            },
                            get: desc.get, enumerable: true, configurable: true
                        });
                    }
                }
              })();
            </script>`, { html: true });
          }
        })
        .on("base", { element(el) { el.remove(); } })
        .on("a", new AttributeRewriter("href", url.origin, targetUrl.href))
        .on("img", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("form", new AttributeRewriter("action", url.origin, targetUrl.href))
        .on("link", new AttributeRewriter("href", url.origin, targetUrl.href))
        .on("script", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("iframe", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("video", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("audio", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("source", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("object", new AttributeRewriter("data", url.origin, targetUrl.href));

      return rewriter.transform(new Response(response.body, {
        status: response.status,
        headers: responseHeaders
      }));
    }

    return new Response(response.body, {
      status: response.status,
      headers: responseHeaders
    });
  }
};

class AttributeRewriter {
  constructor(attr, proxy, target) {
    this.attr = attr;
    this.proxy = proxy;
    this.target = target;
  }
  element(el) {
    const v = el.getAttribute(this.attr);
    if (v && !v.startsWith("data:") && !v.startsWith("javascript:") && !v.startsWith("#")) {
        try { 
            if (v.startsWith("http")) {
                el.setAttribute(this.attr, this.proxy + "/" + v);
            } else {
                el.setAttribute(this.attr, this.proxy + "/" + new URL(v, this.target).href); 
            }
        } catch(e){}
    }
    if (el.tagName === "img" && el.hasAttribute("srcset")) {
        try {
            const val = el.getAttribute("srcset");
            el.setAttribute("srcset", val.replace(/(https?:\/\/)/g, this.proxy + "/$1"));
        } catch(e) {}
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
          if (!targetUrl.startsWith('http')) targetUrl = 'https://' + targetUrl;
          window.location.href = window.location.origin + '/' + targetUrl;
      }
  </script>
</body>
</html>`;
}
