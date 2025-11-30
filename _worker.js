
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
    // 防止目标网站的 sw.js 接管页面导致 404 或缓存错误
    if (actualUrlStr.includes("service-worker") || actualUrlStr.includes("sw.js") || actualUrlStr.includes("worker.js")) {
        return new Response("/* Proxy: Service Worker Disabled */ self.addEventListener('install', () => self.skipWaiting());", {
            headers: { "Content-Type": "application/javascript" }
        });
    }

    // --- 核心修复：URL 清洗 ---
    // 解决 "zh/https://..." 这种重复拼接的问题
    // 如果路径中包含 http/https，提取它及其之后的部分
    const protocolMatch = actualUrlStr.match(/(https?:\/\/.+)/);
    if (protocolMatch) {
        actualUrlStr = protocolMatch[1];
    }

    // 2.1 修正协议 (处理 https:/example.com 或 example.com)
    if (!actualUrlStr.startsWith("http")) {
       // 尝试通过 Referer 还原
       const referer = request.headers.get("Referer");
       let fixed = false;
       if (referer) {
         try {
           const refererObj = new URL(referer);
           if (refererObj.origin === url.origin) {
             const refererTarget = refererObj.pathname.slice(1);
             // 再次检查 Referer 是否包含真正的 URL
             const refMatch = refererTarget.match(/(https?:\/\/.+)/);
             const baseStr = refMatch ? refMatch[1] : refererTarget;
             
             if (baseStr.startsWith("http")) {
                const targetBase = new URL(baseStr);
                // 解决相对路径 ../v1/api
                actualUrlStr = new URL(actualUrlStr, targetBase.href).href;
                fixed = true;
             }
           }
         } catch(e) {}
       }
       // 如果 Referer 没救回来，默认加 https
       if (!fixed) {
           if (actualUrlStr.includes(".") && !actualUrlStr.startsWith("/")) {
               actualUrlStr = "https://" + actualUrlStr;
           } else {
               // 最后的兜底，尝试修复畸形的 protocol
               actualUrlStr = actualUrlStr.replace(/^(https?):\/+/, "$1://");
           }
       }
    }

    // 3. 处理 OPTIONS 预检请求 (解决 CORS 报错)
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
      // 再次清洗，确保没有双重 protocol
      const doubleCheck = actualUrlStr.match(/(https?:\/\/.+)/);
      if (doubleCheck) actualUrlStr = doubleCheck[1];

      if (!actualUrlStr.startsWith("http")) {
          return new Response("Invalid URL: " + actualUrlStr, { status: 404 });
      }
      targetUrl = new URL(actualUrlStr);
    } catch (e) {
      return new Response("URL Parse Error: " + e.message, { status: 400 });
    }

    const newHeaders = new Headers();
    // 复制并过滤请求头
    for (const [key, value] of request.headers) {
      if (key.startsWith("cf-") || UNSAFE_REQUEST_HEADERS.has(key.toLowerCase())) continue;
      newHeaders.set(key, value);
    }

    // 伪装 Host
    newHeaders.set("Host", targetUrl.host);
    
    // Origin: GET 请求通常不发 Origin，只有 POST/PUT 等需要
    // 发送错误的 Origin 可能导致 403
    if (["GET", "HEAD"].includes(request.method)) {
        newHeaders.delete("Origin"); 
    } else {
        newHeaders.set("Origin", targetUrl.origin);
    }

    newHeaders.set("User-Agent", request.headers.get("User-Agent") || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

    // 智能 Referer 处理
    const clientReferer = request.headers.get("Referer");
    // 默认 Referer 为目标首页，这是最安全的
    let newReferer = targetUrl.origin + "/";
    
    // 如果请求的是同一站点的资源，尝试构建更精确的 Referer
    if (clientReferer && clientReferer.startsWith(url.origin)) {
        const realRefererPart = clientReferer.slice(url.origin.length + 1);
        const refProtocolMatch = realRefererPart.match(/(https?:\/\/.+)/);
        if (refProtocolMatch) {
             // 如果上一页是 HTML，使用上一页的完整 URL 作为 Referer
             newReferer = refProtocolMatch[1];
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

    // 6.1 Cookie 修复 
    // 移除 Domain，强制 Path=/, 添加 SameSite=None; Secure 以支持跨域
    const setCookie = responseHeaders.get("Set-Cookie");
    if (setCookie) {
        const newCookie = setCookie
            .replace(/Domain=[^;]+;?/gi, "")
            .replace(/Path=[^;]+;?/gi, "") + "; Path=/; SameSite=None; Secure";
        responseHeaders.set("Set-Cookie", newCookie);
    }
    // 兼容新版 Workers API
    if (typeof responseHeaders.getSetCookie === 'function') {
         const cookies = responseHeaders.getSetCookie();
         responseHeaders.delete("Set-Cookie");
         cookies.forEach(c => {
             let cleanCookie = c.replace(/Domain=[^;]+;?/gi, "").replace(/Path=[^;]+;?/gi, "");
             cleanCookie += "; Path=/; SameSite=None; Secure";
             responseHeaders.append("Set-Cookie", cleanCookie);
         });
    }

    // 6.2 重定向 Location 修复
    const location = responseHeaders.get("Location");
    if (location) {
      try {
        // 处理相对路径重定向
        const absoluteLocation = new URL(location, targetUrl.href).href;
        responseHeaders.set("Location", url.origin + "/" + absoluteLocation);
      } catch (e) {}
    }

    const contentType = responseHeaders.get("Content-Type") || "";

    // 7. 内容重写
    
    // A. M3U8 视频流重写
    if (contentType.includes("mpegurl") || actualUrlStr.endsWith(".m3u8")) {
        let text = await response.text();
        const baseUrl = actualUrlStr.substring(0, actualUrlStr.lastIndexOf("/") + 1);
        text = text.replace(/^(?!#)(?!\s)(.+)$/gm, (match) => {
            match = match.trim();
            if (!match) return match;
            try {
                // 解决相对路径
                const absUrl = match.startsWith("http") ? match : new URL(match, baseUrl).href;
                return url.origin + "/" + absUrl;
            } catch (e) { return match; }
        });
        return new Response(text, { status: response.status, headers: responseHeaders });
    }

    // B. HTML 重写
    if (contentType.includes("text/html")) {
      const rewriter = new HTMLRewriter()
        .on("head", {
          element(element) {
            element.append(`
            <script>
              (function() {
                const PROXY = window.location.origin;
                // 保存当前页面的真实 URL，用于相对路径计算
                const BASE = '${targetUrl.href}'; 
                
                function wrap(u) {
                    if (!u || typeof u !== 'string') return u;
                    // 防止双重代理
                    if (u.includes(PROXY)) return u;
                    if (u.startsWith('data:') || u.startsWith('javascript:') || u.startsWith('#')) return u;
                    if (!u.trim()) return u;
                    
                    try { 
                        // 处理 //example.com
                        if (u.startsWith('//')) return PROXY + '/https:' + u;
                        // 处理绝对路径 /api
                        if (u.startsWith('/')) return PROXY + '/' + new URL(u, BASE).origin + u;
                        // 处理 http
                        if (u.startsWith('http')) return PROXY + '/' + u;
                        // 处理相对路径
                        return PROXY + '/' + new URL(u, BASE).href; 
                    } catch(e) { return u; }
                }
                
                // 1. 劫持 fetch
                const _fetch = window.fetch;
                window.fetch = function(input, init) {
                    if (typeof input === 'string') input = wrap(input);
                    return _fetch(input, init);
                };
                
                // 2. 劫持 XHR
                const _open = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(m, u, ...a) {
                    return _open.call(this, m, wrap(u), ...a);
                };

                // 3. 彻底杀死 Service Worker
                if (navigator.serviceWorker) {
                    navigator.serviceWorker.getRegistrations().then(function(registrations) {
                        for(let registration of registrations) {
                            registration.unregister();
                        }
                    });
                    // 覆盖 register 方法，使其失效
                    navigator.serviceWorker.register = function() {
                        return new Promise(function(resolve, reject) {
                            // 返回一个假的 promise，什么都不做
                            console.log('SW Registration blocked by proxy');
                        });
                    };
                }

                // 4. 劫持 DOM 属性赋值
                const tags = {
                    'img': 'src', 'script': 'src', 'link': 'href', 'a': 'href',
                    'iframe': 'src', 'video': 'src', 'audio': 'src', 'source': 'src', 'form': 'action'
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
                            get: desc.get, 
                            enumerable: true, 
                            configurable: true
                        });
                    }
                }
              })();
            </script>`, { html: true });
          }
        })
        .on("a", new AttributeRewriter("href", url.origin, targetUrl.href))
        .on("img", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("form", new AttributeRewriter("action", url.origin, targetUrl.href))
        .on("link", new AttributeRewriter("href", url.origin, targetUrl.href))
        .on("script", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("iframe", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("video", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("audio", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("source", new AttributeRewriter("src", url.origin, targetUrl.href));

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
  constructor(attr, proxy, target) {
    this.attr = attr;
    this.proxy = proxy;
    this.target = target;
  }
  element(el) {
    const v = el.getAttribute(this.attr);
    if (v && !v.startsWith("data:") && !v.startsWith("javascript:") && !v.startsWith("#")) {
        try { 
            // 解决 HTML 中已经是绝对路径的情况
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
