// _worker.js

/**
 * 响应头清理列表
 * 移除 CSP、HSTS、Frame Options 等可能阻止代理在 iframe 或前端 fetch 中运行的安全头
 */
const UNSAFE_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-xss-protection",
  "x-content-type-options",
  "strict-transport-security", // HSTS
  "clear-site-data"
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

    // 2. 访问 /favicon.ico 直接返回 204
    if (url.pathname === "/favicon.ico") {
        return new Response(null, { status: 204 });
    }

    // 3. 处理 OPTIONS 预检请求 (CORS 增强)
    // 参考 netnr/proxy 对预检请求的处理，返回允许所有源、头和方法
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD",
          "Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers") || "*",
          "Access-Control-Max-Age": "86400" // 缓存预检结果 24 小时
        }
      });
    }

    // 4. 解析目标 URL
    let actualUrlStr = url.pathname.slice(1) + url.search + url.hash;

    // 4.1 尝试从路径中修正协议
    if (actualUrlStr.startsWith("http") && !actualUrlStr.startsWith("http://") && !actualUrlStr.startsWith("https://")) {
        actualUrlStr = actualUrlStr.replace(/^(https?):\/+/, "$1://");
    }

    // 4.2 处理相对路径请求
    if (!actualUrlStr.startsWith("http")) {
      const referer = request.headers.get("Referer");
      if (referer) {
        try {
          const refererObj = new URL(referer);
          if (refererObj.origin === url.origin) {
            let refererTargetStr = refererObj.pathname.slice(1) + refererObj.search;
            // 同样修正 Referer 中的协议格式
            if (refererTargetStr.startsWith("http") && !refererTargetStr.startsWith("http://") && !refererTargetStr.startsWith("https://")) {
                refererTargetStr = refererTargetStr.replace(/^(https?):\/+/, "$1://");
            }

            if (refererTargetStr.startsWith("http")) {
                const targetBase = new URL(refererTargetStr);
                // 使用 url.pathname (带 /) 而不是 actualUrlStr (不带 /)
                // 这样 new URL('/path', base) 会正确解析为 root-relative
                actualUrlStr = new URL(url.pathname + url.search + url.hash, targetBase.href).href;
            }
          }
        } catch (e) {}
      }
    }

    // 5. 准备代理请求
    let targetUrl;
    try {
      if (!actualUrlStr.startsWith("http")) {
          return new Response("Invalid URL (No Protocol): " + actualUrlStr, { 
              status: 400,
              headers: { "Access-Control-Allow-Origin": "*" } 
          });
      }
      targetUrl = new URL(actualUrlStr);
    } catch (e) {
      return new Response("Invalid URL Parse Error: " + actualUrlStr, { 
          status: 400,
          headers: { "Access-Control-Allow-Origin": "*" }
      });
    }

    const newHeaders = new Headers();
    const isSafeMethod = ["GET", "HEAD", "OPTIONS"].includes(request.method);

    // 复制原请求头，但过滤掉 CF 特定头、Cookie 和 Security 头
    for (const [key, value] of request.headers) {
      const lowerKey = key.toLowerCase();
      // 过滤掉可能干扰代理请求的头
      if (lowerKey.startsWith("cf-") || 
          lowerKey === "host" ||
          lowerKey === "origin" ||
          lowerKey === "referer" ||
          lowerKey === "cookie") {
        continue;
      }
      newHeaders.set(key, value);
    }

    // 确保 User-Agent 存在
    if (!newHeaders.has("User-Agent")) {
        newHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36");
    }

    // 关键：伪造 Host
    newHeaders.set("Host", targetUrl.host);
    
    // 只有在非 GET 请求时才发送 Origin，且指向目标源
    if (!isSafeMethod) {
        newHeaders.set("Origin", targetUrl.origin);
    }
    
    // 智能 Referer 处理
    const clientReferer = request.headers.get("Referer");
    if (clientReferer && clientReferer.startsWith(url.origin)) {
        const realRefererPart = clientReferer.slice(url.origin.length + 1);
        if (realRefererPart.startsWith("http")) {
             newHeaders.set("Referer", realRefererPart);
        }
    } else {
        newHeaders.set("Referer", targetUrl.href);
    }

    // 6. 发起请求
    let response;
    try {
      response = await fetch(actualUrlStr, {
        method: request.method,
        headers: newHeaders,
        body: request.body,
        redirect: "manual" // 手动处理重定向以修正 Location 头
      });
    } catch (e) {
      return new Response("Proxy Fetch Error: " + e.message, { 
          status: 502,
          headers: { "Access-Control-Allow-Origin": "*" }
      });
    }

    // 7. 处理响应头 (CORS 增强)
    const responseHeaders = new Headers(response.headers);
    
    // 移除不安全/限制性头
    UNSAFE_HEADERS.forEach(h => responseHeaders.delete(h));

    // 添加完整的 CORS 头
    responseHeaders.set("Access-Control-Allow-Origin", "*");
    responseHeaders.set("Access-Control-Allow-Credentials", "true");
    responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD");
    // 关键：暴露所有头给前端 JS (解决 netnr/proxy 指出的 header 不可见问题)
    responseHeaders.set("Access-Control-Expose-Headers", "*");

    // 重写重定向 Location
    const location = responseHeaders.get("Location");
    if (location) {
      try {
        // 如果是相对路径或绝对路径，都将其包裹在代理 URL 中
        const absoluteLocation = new URL(location, targetUrl.href).href;
        responseHeaders.set("Location", url.origin + "/" + absoluteLocation);
      } catch (e) {}
    }

    const contentType = responseHeaders.get("Content-Type") || "";

    // 8. 内容处理
    
    // A. M3U8 视频流处理
    if (contentType.includes("application/vnd.apple.mpegurl") || 
        contentType.includes("application/x-mpegurl") ||
        actualUrlStr.endsWith(".m3u8")) {
        
        try {
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
        } catch(e) {
            // 如果解析失败，回退到直接返回
        }
    }

    // B. HTML 内容重写 (注入脚本以拦截前端请求)
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

                // 1. 劫持 History API
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

                // 2. 劫持 DOM 属性赋值
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

                // 3. 劫持 fetch
                const oldFetch = window.fetch;
                window.fetch = function(input, init) {
                    let url = input;
                    if (typeof input === 'string') url = wrapUrl(input);
                    else if (input instanceof Request) url = new Request(wrapUrl(input.url), input);
                    return oldFetch(url, init);
                };

                // 4. 劫持 XHR
                const oldOpen = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(method, url, ...args) {
                    return oldOpen.call(this, method, wrapUrl(url), ...args);
                };

                // 5. 禁用 ServiceWorker
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
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders
      }));
    }

    // 9. 其他类型直接返回 (带处理过的 CORS 头)
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  }
};

/**
 * 属性重写器类
 * 用于 HTMLRewriter 重写 HTML 中的相对路径
 */
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
    // 特殊处理 srcset
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
    // 特殊处理 data-src (常见的懒加载属性)
    const dataSrc = element.getAttribute("data-src");
    if (dataSrc) {
        try {
            const resolvedUrl = new URL(dataSrc, this.currentTargetUrl).href;
            element.setAttribute("data-src", this.proxyOrigin + "/" + resolvedUrl);
        } catch (e) {}
    }
  }
}

/**
 * 返回根路径的 UI 界面
 */
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
