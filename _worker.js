
// _worker.js

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
    // 格式: https://proxy-domain.com/https://google.com/foo
    let actualUrlStr = url.pathname.slice(1) + url.search + url.hash;

    // 处理浏览器自动请求的相对路径资源 (如 /favicon.ico, /sw.js)
    if (!actualUrlStr.startsWith("http")) {
      const referer = request.headers.get("Referer");
      if (referer) {
        try {
          const refererUrl = new URL(referer);
          // 如果 Referer 也是我们的代理地址，尝试从中提取真实的目标根域名
          if (refererUrl.origin === url.origin) {
            const refererPath = refererUrl.pathname.slice(1);
            if (refererPath.startsWith("http")) {
              const refererTarget = new URL(refererPath);
              actualUrlStr = new URL(actualUrlStr, refererTarget.href).href;
            }
          }
        } catch (e) {}
      }
    }

    // 如果还是没有协议，尝试补全 (针对手动输入 www.google.com 的情况)
    if (!actualUrlStr.startsWith("http")) {
      if (/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}/.test(actualUrlStr)) {
         actualUrlStr = "https://" + actualUrlStr;
      } else {
         // 无法解析的 URL，视作无效
      }
    }

    // 3. 处理 OPTIONS 预检请求 (解决 CORS 报错)
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
      targetUrl = new URL(actualUrlStr);
    } catch (e) {
      return new Response("Invalid URL: " + actualUrlStr, { status: 400 });
    }

    const newHeaders = new Headers();
    // 复制原请求头，但过滤掉 CF 特定头
    for (const [key, value] of request.headers) {
      if (key.startsWith("cf-")) continue;
      newHeaders.set(key, value);
    }

    // 关键：伪造 Host, Origin
    newHeaders.set("Host", targetUrl.host);
    newHeaders.set("Origin", targetUrl.origin);

    // 智能处理 Referer：避免直接使用代理地址作为 Referer，而是还原真实的 Referer
    const clientReferer = request.headers.get("Referer");
    if (clientReferer && clientReferer.startsWith(url.origin)) {
      try {
        const realReferer = clientReferer.slice(url.origin.length + 1);
        // 只有当解析出的 Referer 是合法 URL 时才使用，否则使用目标 URL
        if (realReferer.startsWith("http")) {
           newHeaders.set("Referer", realReferer);
        } else {
           newHeaders.set("Referer", targetUrl.href);
        }
      } catch (e) {
        newHeaders.set("Referer", targetUrl.href);
      }
    } else {
      // 默认 Fallback
      newHeaders.set("Referer", targetUrl.href);
    }

    // 5. 发起请求
    let response;
    try {
      response = await fetch(actualUrlStr, {
        method: request.method,
        headers: newHeaders,
        body: request.body,
        redirect: "manual" // 手动处理重定向
      });
    } catch (e) {
      return new Response("Proxy Error: " + e.message, { status: 500 });
    }

    // 6. 处理响应头
    const responseHeaders = new Headers(response.headers);
    
    // 移除安全限制头
    UNSAFE_HEADERS.forEach(h => responseHeaders.delete(h));

    // 允许跨域
    responseHeaders.set("Access-Control-Allow-Origin", "*");
    responseHeaders.set("Access-Control-Allow-Credentials", "true");
    responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");

    // 重写重定向 Location
    const location = responseHeaders.get("Location");
    if (location) {
      try {
        // 将重定向的目标地址也包裹在代理中
        const absoluteLocation = new URL(location, targetUrl.href).href;
        responseHeaders.set("Location", url.origin + "/" + absoluteLocation);
      } catch (e) {}
    }

    // 重写 Set-Cookie (移除 Domain 限制)
    const setCookie = responseHeaders.get("Set-Cookie");
    if (setCookie) {
      const newCookie = setCookie
        .replace(/Domain=[^;]+;?/gi, "")
        .replace(/Secure;?/gi, "")
        .replace(/SameSite=[^;]+;?/gi, "");
      responseHeaders.set("Set-Cookie", newCookie);
    }

    const contentType = responseHeaders.get("Content-Type") || "";

    // 7. 处理内容响应
    // A. HTML 内容 (注入脚本 + 重写链接)
    if (contentType.includes("text/html")) {
      const rewriter = new HTMLRewriter()
        .on("head", {
          element(element) {
            // 注入客户端脚本：禁用 ServiceWorker，劫持 fetch/xhr，监听 DOM 变化
            element.append(`
            <script>
              (function() {
                const PROXY_ORIGIN = window.location.origin;
                
                // 1. 禁用 Service Worker
                if (navigator.serviceWorker) {
                    navigator.serviceWorker.register = function() { return new Promise(() => {}); };
                    navigator.serviceWorker.getRegistrations().then(regs => regs.forEach(r => r.unregister()));
                }

                // 2. 劫持 fetch
                const oldFetch = window.fetch;
                window.fetch = function(input, init) {
                    let url = input;
                    if (typeof input === 'string') {
                        if (input.startsWith('http') && !input.startsWith(PROXY_ORIGIN)) {
                            url = PROXY_ORIGIN + '/' + input;
                        } else if (input.startsWith('//')) {
                            url = PROXY_ORIGIN + '/https:' + input;
                        }
                    }
                    return oldFetch(url, init);
                };

                // 3. 劫持 XHR
                const oldOpen = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(method, url, ...args) {
                    if (typeof url === 'string') {
                        if (url.startsWith('http') && !url.startsWith(PROXY_ORIGIN)) {
                            url = PROXY_ORIGIN + '/' + url;
                        } else if (url.startsWith('//')) {
                            url = PROXY_ORIGIN + '/https:' + url;
                        }
                    }
                    return oldOpen.call(this, method, url, ...args);
                };

                // 4. MutationObserver 监听动态插入的标签 (解决动态视频地址)
                const observer = new MutationObserver(mutations => {
                    mutations.forEach(mutation => {
                        mutation.addedNodes.forEach(node => {
                            if (node.nodeType === 1) { 
                                if (['VIDEO', 'AUDIO', 'SOURCE', 'IFRAME', 'IMG'].includes(node.tagName)) {
                                    rewriteAttribute(node);
                                }
                                if (node.querySelectorAll) {
                                    node.querySelectorAll('video, audio, source, iframe, img').forEach(rewriteAttribute);
                                }
                            }
                        });
                        if (mutation.type === 'attributes' && ['src', 'href'].includes(mutation.attributeName)) {
                            rewriteAttribute(mutation.target);
                        }
                    });
                });
                
                function rewriteAttribute(node) {
                    const attr = (node.tagName === 'LINK' || node.tagName === 'A') ? 'href' : 'src';
                    let val = node.getAttribute(attr);
                    // 只处理绝对路径，避免循环引用
                    if (val && val.startsWith('http') && !val.startsWith(PROXY_ORIGIN)) {
                        node.setAttribute(attr, PROXY_ORIGIN + '/' + val);
                    } else if (val && val.startsWith('//')) {
                        node.setAttribute(attr, PROXY_ORIGIN + '/https:' + val);
                    }
                }

                observer.observe(document.documentElement, {
                    childList: true,
                    subtree: true,
                    attributes: true,
                    attributeFilter: ['src', 'href']
                });

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
        .on("object", new AttributeRewriter("data", url.origin, targetUrl.href));

      return rewriter.transform(new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders
      }));
    }
    
    // B. M3U8 视频流 (重写其中的绝对链接)
    if (contentType.includes("application/vnd.apple.mpegurl") || contentType.includes("application/x-mpegurl")) {
        const text = await response.text();
        // 匹配 http:// 或 https:// 开头的行，并在前面加上代理前缀
        const newText = text.replace(/(https?:\/\/[^\s]+)/g, (match) => {
            if (match.startsWith(url.origin)) return match;
            return url.origin + "/" + match;
        });
        return new Response(newText, {
            status: response.status,
            statusText: response.statusText,
            headers: responseHeaders
        });
    }

    // C. 其他内容直接透传
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  }
};

/**
 * HTMLRewriter 处理类
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
      if (value.startsWith("data:") || value.startsWith("#") || value.startsWith("mailto:") || value.startsWith("javascript:")) return;
      try {
        const resolvedUrl = new URL(value, this.currentTargetUrl).href;
        element.setAttribute(this.attributeName, this.proxyOrigin + "/" + resolvedUrl);
      } catch (e) {}
    }
    
    if (element.tagName === "img" && element.hasAttribute("srcset")) {
        const srcset = element.getAttribute("srcset");
        const newSrcset = srcset.split(",").map(part => {
            const [url, desc] = part.trim().split(/\s+/);
            try {
                const resolved = new URL(url, this.currentTargetUrl).href;
                return this.proxyOrigin + "/" + resolved + (desc ? " " + desc : "");
            } catch(e) { return part; }
        }).join(", ");
        element.setAttribute("srcset", newSrcset);
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
                                  <input type="text" id="targetUrl" placeholder="https://www.youtube.com" required>
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
