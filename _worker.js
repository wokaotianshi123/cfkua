// _worker.js

// 想要移除的响应头 (解决 CSP, Frame 限制, 以及清除上游的 CORS 限制)
const UNSAFE_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-xss-protection",
  "x-content-type-options",
  "access-control-allow-origin",
  "access-control-allow-methods",
  "access-control-allow-headers",
  "access-control-expose-headers",
  "access-control-allow-credentials",
  "access-control-max-age",
  // 额外清理可能导致问题的安全头
  "strict-transport-security" 
]);

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // --------------------------------------------------------------------------------
    // 1. CORS 处理逻辑 (参考 Cloudflare-Pages-Universal-Proxy)
    // --------------------------------------------------------------------------------
    const origin = request.headers.get("Origin") || "*";
    const requestHeaders = request.headers.get("Access-Control-Request-Headers");
    
    // 构造动态 CORS 头，支持 Credentials 和各种请求头
    const corsHeaders = {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH",
        "Access-Control-Allow-Headers": requestHeaders || "*",
        "Access-Control-Expose-Headers": "*",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Max-Age": "86400"
    };

    // 处理 OPTIONS 预检请求 (直接返回，不走后续逻辑)
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    // --------------------------------------------------------------------------------
    // 2. 根路径 UI 返回
    // --------------------------------------------------------------------------------
    // 如果是根路径且没有查询参数（意味着不是代理请求），返回欢迎页面
    if (url.pathname === "/" && !url.search) {
      return new Response(getRootHtml(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    // --------------------------------------------------------------------------------
    // 3. 目标 URL 解析
    // --------------------------------------------------------------------------------
    let actualUrlStr = url.pathname.slice(1) + url.search + url.hash;

    // 3.1 尝试从路径中修正协议
    if (actualUrlStr.startsWith("http") && !actualUrlStr.startsWith("http://") && !actualUrlStr.startsWith("https://")) {
        actualUrlStr = actualUrlStr.replace(/^(https?):\/+/, "$1://");
    }

    // 3.2 处理相对路径请求
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
                // 这样 new URL('/path', base) 会正确解析为 root-relative，而不是 path-relative
                actualUrlStr = new URL(url.pathname + url.search + url.hash, targetBase.href).href;
            }
          }
        } catch (e) {}
      }
    }

    // --------------------------------------------------------------------------------
    // 4. 准备代理请求
    // --------------------------------------------------------------------------------
    let targetUrl;
    try {
      if (!actualUrlStr.startsWith("http")) {
          return new Response("Invalid URL (No Protocol): " + actualUrlStr, { status: 400 });
      }
      targetUrl = new URL(actualUrlStr);
    } catch (e) {
      return new Response("Invalid URL Parse Error: " + actualUrlStr, { status: 400 });
    }

    const newHeaders = new Headers();
    const isSafeMethod = ["GET", "HEAD", "OPTIONS"].includes(request.method);

    // 复制原请求头，但过滤掉 CF 特定头、Cookie 和 Security 头
    for (const [key, value] of request.headers) {
      const lowerKey = key.toLowerCase();
      if (lowerKey.startsWith("cf-") || 
          lowerKey.startsWith("sec-") || 
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
    
    // 只有在非 GET 请求时才发送 Origin
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
        // 如果没有 Referer，默认给一个目标根目录，防止某些防盗链
        newHeaders.set("Referer", targetUrl.origin + "/");
    }

    // --------------------------------------------------------------------------------
    // 5. 发起请求
    // --------------------------------------------------------------------------------
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

    // --------------------------------------------------------------------------------
    // 6. 处理响应头
    // --------------------------------------------------------------------------------
    const responseHeaders = new Headers(response.headers);
    
    // 清理不安全的头和上游的 CORS 头
    UNSAFE_HEADERS.forEach(h => responseHeaders.delete(h));

    // 应用动态生成的 CORS 头
    Object.keys(corsHeaders).forEach(key => {
        responseHeaders.set(key, corsHeaders[key]);
    });

    // 重写重定向 Location
    const location = responseHeaders.get("Location");
    if (location) {
      try {
        const absoluteLocation = new URL(location, targetUrl.href).href;
        responseHeaders.set("Location", url.origin + "/" + absoluteLocation);
      } catch (e) {}
    }

    const contentType = responseHeaders.get("Content-Type") || "";

    // --------------------------------------------------------------------------------
    // 7. 内容重写 (M3U8 & HTML)
    // --------------------------------------------------------------------------------
    
    // A. M3U8 视频流
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

    // B. HTML 内容
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

                // 1. 劫持 History API (pushState, replaceState) 防止 SPA 移除代理前缀
                const oldPushState = history.pushState;
                const oldReplaceState = history.replaceState;
                
                function wrapHistoryArgs(args) {
                    // args: [state, title, url]
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

                // 2. 劫持原生属性赋值
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
                                const wrapped = wrapUrl(val);
                                originalSet.call(this, wrapped);
                            },
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
                    if (typeof input === 'string') {
                        url = wrapUrl(input);
                    }
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
