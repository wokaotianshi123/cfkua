// _workers.js

// 想要移除的响应头 (解决 CSP, Frame 限制等问题)
const UNSAFE_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-xss-protection",
  "x-content-type-options"
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
    // 兼容 encodeURIComponent 编码的 URL (来自 UI) 和直接拼接的 URL
    let path = url.pathname.slice(1);
    // 尝试解码，如果解码失败则保留原样
    try {
        path = decodeURIComponent(path);
    } catch (e) {}
    
    let actualUrlStr = path + url.search + url.hash;

    // 2.1 尝试从路径中修正协议 (e.g. https:/google.com -> https://google.com)
    if (actualUrlStr.startsWith("http") && !actualUrlStr.startsWith("http://") && !actualUrlStr.startsWith("https://")) {
        actualUrlStr = actualUrlStr.replace(/^(https?):\/+/, "$1://");
    }

    // 2.2 处理相对路径请求 (Referer fix)
    // 当浏览器请求 /path/to/resource.js 时，我们需要根据 Referer 恢复出 https://target.com/path/to/resource.js
    if (!actualUrlStr.startsWith("http")) {
      const referer = request.headers.get("Referer");
      if (referer) {
        try {
          const refererObj = new URL(referer);
          if (refererObj.origin === url.origin) {
            // Referer 也是代理过的地址，提取其中的真实目标
            let refererPath = refererObj.pathname.slice(1);
            try { refererPath = decodeURIComponent(refererPath); } catch(e){}
            
            let refererTargetStr = refererPath + refererObj.search;
            
            // 修正 Referer 中的协议格式
            if (refererTargetStr.startsWith("http") && !refererTargetStr.startsWith("http://") && !refererTargetStr.startsWith("https://")) {
                refererTargetStr = refererTargetStr.replace(/^(https?):\/+/, "$1://");
            }

            if (refererTargetStr.startsWith("http")) {
                const targetBase = new URL(refererTargetStr);
                // 使用原始 url.pathname (带 /) 而不是 actualUrlStr (不带 /)
                // 这样 new URL('/path', base) 会正确解析为 root-relative，而不是 path-relative
                actualUrlStr = new URL(url.pathname + url.search + url.hash, targetBase.href).href;
            }
          }
        } catch (e) {}
      }
    }

    // 3. 处理 OPTIONS 预检请求
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
          "Access-Control-Allow-Headers": "*"
        }
      });
    }

    // 4. 准备代理请求
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

    // 复制原请求头，但过滤掉 CF 特定头和 Security 头
    // 保留 Cookie 以支持需要登录的站点
    for (const [key, value] of request.headers) {
      const lowerKey = key.toLowerCase();
      if (lowerKey.startsWith("cf-") || 
          lowerKey.startsWith("sec-")) {
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
        // 尝试解码 Referer
        let decodedReferer = realRefererPart;
        try { decodedReferer = decodeURIComponent(realRefererPart); } catch(e){}
        
        if (decodedReferer.startsWith("http")) {
             newHeaders.set("Referer", decodedReferer);
        }
    } 

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
    UNSAFE_HEADERS.forEach(h => responseHeaders.delete(h));

    responseHeaders.set("Access-Control-Allow-Origin", "*");
    responseHeaders.set("Access-Control-Allow-Credentials", "true");
    responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");

    // 重写重定向 Location
    const location = responseHeaders.get("Location");
    if (location) {
      try {
        const absoluteLocation = new URL(location, targetUrl.href).href;
        // 保持使用 encodeURIComponent 以配合 UI 和解码逻辑
        responseHeaders.set("Location", url.origin + "/" + encodeURIComponent(absoluteLocation));
      } catch (e) {}
    }

    const contentType = responseHeaders.get("Content-Type") || "";

    // 7. 内容处理
    
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
                // 对 M3U8 内的链接也进行编码，防止被客户端广告屏蔽插件误杀
                return url.origin + "/" + encodeURIComponent(absoluteUrl);
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
                        // 编码 URL 以避免被客户端广告拦截器 (如 uBlock) 根据路径规则屏蔽
                        return PROXY_ORIGIN + '/' + encodeURIComponent(absolute);
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
                                 const newUrl = url.origin + "/" + encodeURIComponent(absoluteUrl);
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
        // 编码 URL，规避客户端广告过滤
        element.setAttribute(this.attributeName, this.proxyOrigin + "/" + encodeURIComponent(resolvedUrl));
      } catch (e) {}
    }
    if (element.tagName === "img" && element.hasAttribute("srcset")) {
        const srcset = element.getAttribute("srcset");
        const newSrcset = srcset.split(",").map(part => {
            const [u, d] = part.trim().split(/\s+/);
            try {
                const resolved = new URL(u, this.currentTargetUrl).href;
                return this.proxyOrigin + "/" + encodeURIComponent(resolved) + (d ? " " + d : "");
            } catch(e) { return part; }
        }).join(", ");
        element.setAttribute("srcset", newSrcset);
    }
    const dataSrc = element.getAttribute("data-src");
    if (dataSrc) {
        try {
            const resolvedUrl = new URL(dataSrc, this.currentTargetUrl).href;
            element.setAttribute("data-src", this.proxyOrigin + "/" + encodeURIComponent(resolvedUrl));
        } catch (e) {}
    }
  }
}

function getRootHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <link href="https://s4.zstatic.net/ajax/libs/materialize/1.0.0/css/materialize.min.css" rel="stylesheet">
  <title>Proxy Everything</title>
  <link rel="icon" type="image/png" href="https://s2.hdslb.com/bfs/openplatform/1682b11880f5c53171217a03c8adc9f2e2a27fcf.png@100w.webp">
  <meta name="Description" content="Proxy Everything with CF Workers.">
  <meta property="og:description" content="Proxy Everything with CF Workers.">
  <meta property="og:image" content="https://s2.hdslb.com/bfs/openplatform/1682b11880f5c53171217a03c8adc9f2e2a27fcf.png@100w.webp">
  <meta name="robots" content="index, follow">
  <meta http-equiv="Content-Language" content="zh-CN">
  <meta name="copyright" content="Copyright © ymyuuu">
  <meta name="author" content="ymyuuu">
  <link rel="apple-touch-icon-precomposed" sizes="120x120" href="https://s2.hdslb.com/bfs/openplatform/1682b11880f5c53171217a03c8adc9f2e2a27fcf.png@100w.webp">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0, user-scalable=no">
  <style>
      body, html {
          height: 100%;
          margin: 0;
      }
      .background {
          background-size: cover;
          background-position: center;
          height: 100%;
          display: flex;
          align-items: center;
          justify-content: center;
      }
      .card {
          background-color: rgba(255, 255, 255, 0.8);
          transition: background-color 0.3s ease, box-shadow 0.3s ease;
      }
      .card:hover {
          background-color: rgba(255, 255, 255, 1);
          box-shadow: 0px 8px 16px rgba(0, 0, 0, 0.3);
      }
      .input-field input[type=text] {
          color: #2c3e50;
      }
      .input-field input[type=text]:focus+label {
          color: #2c3e50 !important;
      }
      .input-field input[type=text]:focus {
          border-bottom: 1px solid #2c3e50 !important;
          box-shadow: 0 1px 0 0 #2c3e50 !important;
      }
      @media (prefers-color-scheme: dark) {
          body, html {
              background-color: #121212;
              color: #e0e0e0;
          }
          .card {
              background-color: rgba(33, 33, 33, 0.9);
              color: #ffffff;
          }
          .card:hover {
              background-color: rgba(50, 50, 50, 1);
              box-shadow: 0px 8px 16px rgba(0, 0, 0, 0.6);
          }
          .input-field input[type=text] {
              color: #ffffff;
          }
          .input-field input[type=text]:focus+label {
              color: #ffffff !important;
          }
          .input-field input[type=text]:focus {
              border-bottom: 1px solid #ffffff !important;
              box-shadow: 0 1px 0 0 #ffffff !important;
          }
          label {
              color: #cccccc;
          }
      }
  </style>
</head>
<body>
  <div class="background">
      <div class="container">
          <div class="row">
              <div class="col s12 m8 offset-m2 l6 offset-l3">
                  <div class="card">
                      <div class="card-content">
                          <span class="card-title center-align"><i class="material-icons left">link</i>Proxy Everything</span>
                          <form id="urlForm" onsubmit="redirectToProxy(event)">
                              <div class="input-field">
                                  <input type="text" id="targetUrl" placeholder="在此输入目标地址" required>
                                  <label for="targetUrl">目标地址</label>
                              </div>
                              <button type="submit" class="btn waves-effect waves-light teal darken-2 full-width">跳转</button>
                          </form>
                      </div>
                  </div>
              </div>
          </div>
      </div>
  </div>
  <script src="https://s4.zstatic.net/ajax/libs/materialize/1.0.0/js/materialize.min.js"></script>
  <script>
      function redirectToProxy(event) {
          event.preventDefault();
          const targetUrl = document.getElementById('targetUrl').value.trim();
          const currentOrigin = window.location.origin;
          window.open(currentOrigin + '/' + encodeURIComponent(targetUrl), '_blank');
      }
  </script>
</body>
</html>`;
}
