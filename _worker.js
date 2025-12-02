
// _worker.js

// 想要移除的响应头 (解决 CSP, Frame 限制等问题)
const UNSAFE_RESPONSE_HEADERS = new Set([
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
    let actualUrlStr = url.pathname.slice(1) + url.search + url.hash;

    // 2.1 尝试从路径中修正协议
    if (actualUrlStr.startsWith("http") && !actualUrlStr.startsWith("http://") && !actualUrlStr.startsWith("https://")) {
        actualUrlStr = actualUrlStr.replace(/^(https?):\/+/, "$1://");
    }

    // 2.2 处理相对路径请求
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
          "Access-Control-Allow-Headers": "*",
          "Access-Control-Allow-Credentials": "true"
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
    
    // -----------------------------------------------------------
    // Header 复制与清洗
    // -----------------------------------------------------------
    for (const [key, value] of request.headers) {
      const lowerKey = key.toLowerCase();
      // 过滤 Cloudflare 头、Sec-Fetch 头（避免暴露来源不一致）、以及需要重写的头
      if (lowerKey.startsWith("cf-")) continue;
      // 过滤 Sec-Fetch 头，防止目标服务器判断为 Cross-Site 而拦截
      // 虽然 Fetch API 可能自动管理这些，但显式清理更安全
      if (lowerKey.startsWith("sec-fetch-")) continue; 
      
      if (["host", "referer", "origin", "user-agent"].includes(lowerKey)) continue;

      newHeaders.set(key, value);
    }

    // -----------------------------------------------------------
    // 关键修复: 智能 Referer 与 Origin 伪造
    // -----------------------------------------------------------
    
    // 1. Host
    newHeaders.set("Host", targetUrl.host);

    // 2. Referer 处理
    // 我们尝试从客户端的 Referer 中提取出原始目标的 URL 结构
    const clientReferer = request.headers.get("Referer");
    let upstreamReferer = "";

    if (clientReferer && clientReferer.startsWith(url.origin)) {
        // 如果 Referer 是代理地址 (e.g. https://proxy.com/https://target.com/video/123)
        // 剥离代理前缀，还原为 https://target.com/video/123
        const rawRefererPath = clientReferer.slice(url.origin.length);
        // 去掉可能存在的起始 '/'
        let cleanPath = rawRefererPath.startsWith('/') ? rawRefererPath.slice(1) : rawRefererPath;
        
        // 修正协议 (handle http:/example.com case if needed, though simple slice usually works if proxy structure is consistent)
        if (cleanPath.startsWith("http") && !cleanPath.startsWith("http://") && !cleanPath.startsWith("https://")) {
            cleanPath = cleanPath.replace(/^(https?):\/+/, "$1://");
        }
        
        if (cleanPath.startsWith("http")) {
            upstreamReferer = cleanPath;
        }
    }

    // 如果无法从客户端 Referer 提取（例如直接访问或 Referer 为空），
    // 或者是 sub-resource 请求但没有携带正确 Referer，
    // 我们默认伪造为 Target 的 Origin + Path (Self Referer) 或者 Origin Root
    // 为了通过防盗链，通常 "Referer: https://target.com/some/page" 访问 "https://target.com/video.m3u8" 是合法的。
    // 这里我们保守一点：如果提取不到，就使用 targetUrl.origin + "/"，这能通过大多数 Origin Check。
    if (!upstreamReferer) {
        upstreamReferer = targetUrl.origin + "/";
    }

    newHeaders.set("Referer", upstreamReferer);
    
    // 3. Origin 处理 (CORS / POST)
    newHeaders.set("Origin", targetUrl.origin);

    // 4. User-Agent
    // 使用较新的 Chrome User-Agent
    newHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");

    // 5. 移除可能暴露 IP 的头
    newHeaders.delete("X-Forwarded-For");
    newHeaders.delete("X-Real-IP");


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
    
    // 处理 Set-Cookie (移除 Domain 限制)
    const setCookie = responseHeaders.get("Set-Cookie");
    if (setCookie) {
        const newCookie = setCookie.replace(/Domain=[^;]+;?/gi, "");
        responseHeaders.set("Set-Cookie", newCookie);
    }

    // 重写重定向 Location
    const location = responseHeaders.get("Location");
    if (location) {
      try {
        const absoluteLocation = new URL(location, targetUrl.href).href;
        responseHeaders.set("Location", url.origin + "/" + absoluteLocation);
        
        if ([301, 302, 303, 307, 308].includes(response.status)) {
            return new Response(null, {
                status: response.status,
                headers: responseHeaders
            });
        }
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

                const oldFetch = window.fetch;
                window.fetch = function(input, init) {
                    let url = input;
                    if (typeof input === 'string') {
                        url = wrapUrl(input);
                    }
                    return oldFetch(url, init);
                };

                const oldOpen = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(method, url, ...args) {
                    return oldOpen.call(this, method, wrapUrl(url), ...args);
                };
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
        .on("track", new AttributeRewriter("src", url.origin, targetUrl.href));

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
    
    if (element.tagName === "video") {
        const poster = element.getAttribute("poster");
        if (poster) {
             try {
                const resolvedUrl = new URL(poster, this.currentTargetUrl).href;
                element.setAttribute("poster", this.proxyOrigin + "/" + resolvedUrl);
            } catch (e) {}
        }
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
