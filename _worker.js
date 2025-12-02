
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
          // 如果解析失败，尝试作为相对路径处理（假设目标是上一次访问的 host）
          // 这里简单处理：如果实在解析不出，报错
          return new Response("Invalid URL (No Protocol): " + actualUrlStr, { status: 400 });
      }
      targetUrl = new URL(actualUrlStr);
    } catch (e) {
      return new Response("Invalid URL Parse Error: " + actualUrlStr, { status: 400 });
    }

    const newHeaders = new Headers();
    const isSafeMethod = ["GET", "HEAD", "OPTIONS"].includes(request.method);

    // -----------------------------------------------------------
    // 关键修复 1: Header 处理逻辑增强
    // -----------------------------------------------------------
    for (const [key, value] of request.headers) {
      const lowerKey = key.toLowerCase();
      // 过滤掉 CF 特定头
      if (lowerKey.startsWith("cf-")) continue;
      
      // 修复：允许 Cookie 通过！很多网站依靠 Cookie 验证身份或 Session
      // 仅过滤掉 host, referer, origin, sec- 等由我们手动构建的头
      if (["host", "referer", "origin"].includes(lowerKey)) continue;

      newHeaders.set(key, value);
    }

    // -----------------------------------------------------------
    // 关键修复 2: 伪造身份 (Anti-Hotlink / Bot Detection Bypass)
    // -----------------------------------------------------------
    
    // 强制 Host
    newHeaders.set("Host", targetUrl.host);

    // 强制伪造 Referer：告诉目标服务器，我就是从你的网站点过来的
    // 视频网站通常检查 Referer 是否与视频文件同域
    newHeaders.set("Referer", targetUrl.origin + "/"); 
    
    // 强制伪造 Origin (主要用于 POST 请求或 CORS 检查)
    newHeaders.set("Origin", targetUrl.origin);

    // 补全 User-Agent (防止某些服务器拒绝空 UA)
    if (!newHeaders.has("User-Agent")) {
        newHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");
    }

    // 添加一些浏览器标准头，让请求看起来更像真实浏览器
    newHeaders.set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8");
    if (!newHeaders.has("Accept")) {
        newHeaders.set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
    }

    // 移除可能暴露代理身份的头 (X-Forwarded-For 由 CF Worker 自动处理，我们尽量减少额外痕迹)
    newHeaders.delete("X-Forwarded-For");
    newHeaders.delete("X-Real-IP");

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
      return new Response("Proxy Fetch Error: " + e.message, { status: 502 });
    }

    // 6. 处理响应头
    const responseHeaders = new Headers(response.headers);
    UNSAFE_RESPONSE_HEADERS.forEach(h => responseHeaders.delete(h));

    // 允许跨域，方便本地开发或由其他前端调用
    responseHeaders.set("Access-Control-Allow-Origin", "*");
    responseHeaders.set("Access-Control-Allow-Credentials", "true");
    responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    
    // 修复：确保 Set-Cookie 能正确传递回客户端
    // 部分网站设置 Cookie 时指定了 Domain，浏览器可能会因为 Domain 不匹配当前代理域名而拒绝写入
    // 我们简单粗暴地移除 Domain 属性，让 Cookie 写入当前代理域
    const setCookie = responseHeaders.get("Set-Cookie");
    if (setCookie) {
        // 简单的替换逻辑，移除 Domain=xxx; 
        const newCookie = setCookie.replace(/Domain=[^;]+;?/gi, "");
        responseHeaders.set("Set-Cookie", newCookie);
    }

    // 重写重定向 Location
    const location = responseHeaders.get("Location");
    if (location) {
      try {
        // 处理相对路径重定向
        const absoluteLocation = new URL(location, targetUrl.href).href;
        responseHeaders.set("Location", url.origin + "/" + absoluteLocation);
        
        // 如果是 301/302/303/307/308，我们需要修改 Location，让浏览器跳回代理地址
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
    
    // A. M3U8 视频流 (常见于视频网站)
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

                // 劫持 History API
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

                // 劫持 fetch
                const oldFetch = window.fetch;
                window.fetch = function(input, init) {
                    let url = input;
                    if (typeof input === 'string') {
                        url = wrapUrl(input);
                    }
                    return oldFetch(url, init);
                };

                // 劫持 XHR
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
        .on("video", new AttributeRewriter("src", url.origin, targetUrl.href)) // 视频标签
        .on("audio", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("source", new AttributeRewriter("src", url.origin, targetUrl.href)) // source 标签
        .on("track", new AttributeRewriter("src", url.origin, targetUrl.href));

      return rewriter.transform(new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders
      }));
    }

    // 其他内容直接返回
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
    
    // 处理 srcset (图片响应式)
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

    // 处理 data-src (懒加载常见)
    const dataSrc = element.getAttribute("data-src");
    if (dataSrc) {
        try {
            const resolvedUrl = new URL(dataSrc, this.currentTargetUrl).href;
            element.setAttribute("data-src", this.proxyOrigin + "/" + resolvedUrl);
        } catch (e) {}
    }
    
    // 处理 poster (视频封面)
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
