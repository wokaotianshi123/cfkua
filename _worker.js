// _worker.js

// 1. 想要移除的响应头
const UNSAFE_RESPONSE_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-xss-protection",
  "x-content-type-options"
]);

// 2. 想要移除的请求头
const UNSAFE_REQUEST_HEADERS = new Set([
  "x-forwarded-for",
  "x-real-ip",
  "via",
  "cf-connecting-ip",
  "cf-worker",
  "forwarded"
]);

// 客户端注入脚本 (不仅用于HTML，也用于Web Worker)
const CLIENT_SCRIPT = `
(function() {
  const PROXY = self.location.origin;
  // 尝试从当前脚本路径推断 BASE，或者是全局定义
  const BASE = self.__TARGET_BASE__ || (typeof document !== 'undefined' ? document.baseURI : self.location.href);

  function wrap(u) {
      if (!u || typeof u !== 'string') return u;
      // 忽略数据协议和锚点
      if (u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('javascript:') || u.startsWith('#')) return u;
      
      // 防止递归：如果 URL 已经包含了代理域名，则不处理
      if (u.includes(PROXY)) return u;

      u = u.trim();
      
      // 处理 //example.com
      if (u.startsWith('//')) return PROXY + '/https:' + u;
      
      // 处理相对路径 /path
      if (u.startsWith('/')) {
          try { 
            // 使用 URL 对象解析，确保基于目标域名
            return PROXY + '/' + new URL(u, BASE).origin + u; 
          } catch(e) { 
            return PROXY + '/https://' + u; 
          }
      }
      
      // 处理绝对路径 http
      if (u.startsWith('http')) return PROXY + '/' + u;
      
      // 处理相对路径 (无斜杠)
      try { return PROXY + '/' + new URL(u, BASE).href; } catch (e) { return u; }
  }

  // --- 拦截器核心 ---

  // 1. Fetch & Request
  const _Request = self.Request;
  if (_Request) {
      self.Request = function(input, init) {
          let wrappedInput = input;
          if (typeof input === 'string') wrappedInput = wrap(input);
          else if (input instanceof _Request) {
               if (!input.url.includes(PROXY)) wrappedInput = new _Request(wrap(input.url), input);
          } else if (input instanceof URL) wrappedInput = wrap(input.href);
          return new _Request(wrappedInput, init);
      };
      self.Request.prototype = _Request.prototype;
  }

  const _fetch = self.fetch;
  if (_fetch) {
      self.fetch = function(input, init) {
          let wrappedInput = input;
          if (typeof input === 'string') wrappedInput = wrap(input);
          else if (input instanceof URL) wrappedInput = wrap(input.href);
          // 如果是 Request 对象，Request 构造函数已经被拦截，这里不需要重复处理，除非直接传了原生 Request
          return _fetch(wrappedInput, init);
      };
  }

  // 2. XHR
  if (typeof XMLHttpRequest !== 'undefined') {
      const _open = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function(m, u, ...a) {
          return _open.call(this, m, wrap(u), ...a);
      };
  }

  // 只有主线程需要拦截 DOM
  if (typeof document !== 'undefined') {
      
      // 3. setAttribute (覆盖动态创建元素)
      const _setAttribute = Element.prototype.setAttribute;
      Element.prototype.setAttribute = function(name, value) {
          if (['src', 'href', 'action', 'data', 'poster'].includes(name.toLowerCase())) {
              return _setAttribute.call(this, name, wrap(value));
          }
          return _setAttribute.call(this, name, value);
      };

      // 4. innerHTML (覆盖字符串拼接注入)
      const _innerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
      if (_innerHTML && _innerHTML.set) {
          Object.defineProperty(Element.prototype, 'innerHTML', {
              set: function(html) {
                  // 简单正则替换常见属性，性能损耗换取覆盖率
                  // 替换 src="..." href="..." url(...)
                  if (typeof html === 'string') {
                      const newHtml = html.replace(/(src|href|poster|data|action)=["']([^"']+)["']/g, (match, attr, url) => {
                          return \`\${attr}="\${wrap(url)}"\`;
                      }).replace(/url\(([^)]+)\)/g, (match, url) => {
                          return \`url(\${wrap(url.replace(/['"]/g,''))})\`;
                      });
                      _innerHTML.set.call(this, newHtml);
                  } else {
                      _innerHTML.set.call(this, html);
                  }
              },
              get: _innerHTML.get
          });
      }

      // 5. Style background-image
      const _setProperty = CSSStyleDeclaration.prototype.setProperty;
      CSSStyleDeclaration.prototype.setProperty = function(prop, value, priority) {
          if (prop === 'background-image' || prop === 'background') {
              value = value.replace(/url\(([^)]+)\)/g, (match, url) => \`url(\${wrap(url.replace(/['"]/g,''))})\`);
          }
          return _setProperty.call(this, prop, value, priority);
      };

      // 6. 禁用 Service Worker
      if (navigator.serviceWorker) {
          navigator.serviceWorker.register = () => new Promise(() => {});
          navigator.serviceWorker.getRegistrations().then(rs => rs.forEach(r => r.unregister()));
      }

      // 7. 直接属性赋值 (img.src = ...)
      const tags = {
          'img': 'src', 'script': 'src', 'link': 'href', 'a': 'href',
          'iframe': 'src', 'video': 'src', 'audio': 'src', 'source': 'src', 
          'form': 'action', 'object': 'data', 'embed': 'src'
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
  }
})();
`;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. 访问根目录
    if (url.pathname === "/") {
      return new Response(getRootHtml(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    // 2. 解析目标 URL
    let actualUrlStr = url.pathname.slice(1) + url.search + url.hash;

    // --- 核心修复：防止 Service Worker ---
    if (actualUrlStr.includes("service-worker") || actualUrlStr.includes("sw.js")) {
        return new Response("/* Disabled */", { headers: { "Content-Type": "application/javascript" }});
    }

    // --- 核心修复：防递归清洗 ---
    // 如果 URL 包含了我们自己的域名，说明发生了循环，需要剥离
    if (actualUrlStr.includes(url.host)) {
        // 尝试提取最后一个 http
        const lastHttp = actualUrlStr.lastIndexOf("http");
        if (lastHttp !== -1) {
            actualUrlStr = actualUrlStr.substring(lastHttp);
        }
    } else {
        // 常规清洗：取第一个 http
        const greedyMatch = actualUrlStr.match(/(https?:\/\/.+)/);
        if (greedyMatch) {
            actualUrlStr = greedyMatch[1];
        }
    }

    // --- 2.1 补全 URL (处理 /static 404) ---
    if (!actualUrlStr.startsWith("http")) {
       let fixed = false;
       // 策略：Cookie 还原
       const cookies = request.headers.get("Cookie") || "";
       const targetCookie = cookies.match(/__proxy_target__=([^;]+)/);
       if (targetCookie) {
           try {
               const baseOrigin = decodeURIComponent(targetCookie[1]);
               const baseObj = new URL(baseOrigin);
               // 组合 base 和 path
               actualUrlStr = new URL(actualUrlStr, baseObj.href).href;
               fixed = true;
           } catch(e) {}
       }
       
       if (!fixed) {
           // 兜底：如果有点号，假设是域名
           if (actualUrlStr.includes(".") && !actualUrlStr.startsWith("/")) {
               actualUrlStr = "https://" + actualUrlStr;
           } else {
               return new Response(`Cannot resolve URL: ${actualUrlStr}`, { status: 404 });
           }
       }
    }

    // 3. OPTIONS 预检
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "*",
          "Access-Control-Allow-Headers": "*"
        }
      });
    }

    // 4. 准备请求
    let targetUrl;
    try {
      targetUrl = new URL(actualUrlStr);
    } catch (e) {
      return new Response("URL Error: " + e.message, { status: 400 });
    }

    const newHeaders = new Headers();
    for (const [key, value] of request.headers) {
      if (key.startsWith("cf-") || UNSAFE_REQUEST_HEADERS.has(key.toLowerCase())) continue;
      newHeaders.set(key, value);
    }
    newHeaders.set("Host", targetUrl.host);
    
    // Referer 欺骗
    newHeaders.set("Referer", targetUrl.origin + "/");
    
    // Origin 欺骗 (只对非 GET)
    if (request.method !== "GET" && request.method !== "HEAD") {
        newHeaders.set("Origin", targetUrl.origin);
    } else {
        newHeaders.delete("Origin");
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
      return new Response("Proxy Error: " + e.message, { status: 502 });
    }

    // 6. 响应头处理
    const responseHeaders = new Headers(response.headers);
    UNSAFE_RESPONSE_HEADERS.forEach(h => responseHeaders.delete(h));
    responseHeaders.set("Access-Control-Allow-Origin", "*");
    
    // 种下目标域名 Cookie，用于后续 404 修复
    const contentType = responseHeaders.get("Content-Type") || "";
    if (contentType.includes("text/html")) {
        responseHeaders.append("Set-Cookie", `__proxy_target__=${encodeURIComponent(targetUrl.origin)}; Path=/; SameSite=None; Secure; HttpOnly`);
    }

    // 修复 Set-Cookie
    const setCookie = responseHeaders.get("Set-Cookie");
    if (setCookie) {
         // 简单粗暴替换，移除 Domain
         const newCookie = setCookie.replace(/Domain=[^;]+;?/gi, "").replace(/Path=[^;]+;?/gi, "") + "; Path=/; SameSite=None; Secure";
         responseHeaders.set("Set-Cookie", newCookie);
    }
    
    // 修复 Location
    const location = responseHeaders.get("Location");
    if (location) {
        try {
            const absLoc = new URL(location, targetUrl.href).href;
            responseHeaders.set("Location", url.origin + "/" + absLoc);
        } catch(e){}
    }

    // 7. 内容重写
    // A. M3U8 文件
    if (actualUrlStr.endsWith(".m3u8") || contentType.includes("mpegurl")) {
        const text = await response.text();
        const baseUrl = actualUrlStr.substring(0, actualUrlStr.lastIndexOf("/") + 1);
        const newText = text.replace(/^(?!#)(?!\s)(.+)$/gm, (match) => {
            match = match.trim();
            if(!match) return match;
            try {
                const abs = match.startsWith("http") ? match : new URL(match, baseUrl).href;
                return url.origin + "/" + abs;
            } catch(e) { return match; }
        });
        return new Response(newText, { status: response.status, headers: responseHeaders });
    }

    // B. Worker 脚本 (检测到请求是 Worker 脚本时，注入拦截器)
    const isWorkerRequest = request.headers.get("Sec-Fetch-Dest") === "worker" || 
                            request.headers.get("Sec-Fetch-Dest") === "sharedworker";
    
    if (isWorkerRequest || (contentType.includes("javascript") && actualUrlStr.includes("player"))) {
        const text = await response.text();
        // 注入全局变量 __TARGET_BASE__ 以便 Worker 内部能解析相对路径
        const inject = `self.__TARGET_BASE__ = '${targetUrl.href}';\n` + CLIENT_SCRIPT;
        return new Response(inject + text, { status: response.status, headers: responseHeaders });
    }

    // C. HTML 页面
    if (contentType.includes("text/html")) {
        const rewriter = new HTMLRewriter()
            .on("head", {
                element(element) {
                    // 注入全局变量和脚本
                    element.append(`<script>window.__TARGET_BASE__ = '${targetUrl.href}'; ${CLIENT_SCRIPT}</script>`, { html: true });
                }
            })
            // 移除 base 标签，防止干扰
            .on("base", { element(el) { el.remove(); } })
            // 静态属性重写
            .on("a", new AttributeRewriter("href", url.origin, targetUrl.href))
            .on("img", new AttributeRewriter("src", url.origin, targetUrl.href))
            .on("form", new AttributeRewriter("action", url.origin, targetUrl.href))
            .on("link", new AttributeRewriter("href", url.origin, targetUrl.href))
            .on("script", new AttributeRewriter("src", url.origin, targetUrl.href))
            .on("iframe", new AttributeRewriter("src", url.origin, targetUrl.href))
            .on("video", new AttributeRewriter("src", url.origin, targetUrl.href))
            .on("audio", new AttributeRewriter("src", url.origin, targetUrl.href))
            .on("source", new AttributeRewriter("src", url.origin, targetUrl.href));
        
        return rewriter.transform(response);
    }

    return new Response(response.body, { status: response.status, headers: responseHeaders });
  }
};

// HTMLRewriter 辅助类
class AttributeRewriter {
  constructor(attr, proxy, target) {
    this.attr = attr;
    this.proxy = proxy;
    this.target = target;
  }
  element(el) {
    const v = el.getAttribute(this.attr);
    if (v && !v.startsWith("data:") && !v.startsWith("#") && !v.startsWith("javascript:")) {
        try {
            const abs = v.startsWith("http") ? v : new URL(v, this.target).href;
            el.setAttribute(this.attr, this.proxy + "/" + abs);
        } catch(e) {}
    }
    // 处理 srcset
    if (el.tagName === "img" && el.hasAttribute("srcset")) {
        const val = el.getAttribute("srcset");
        if (val) {
             const newVal = val.replace(/((https?:\/\/[^\s]+)|(\/[^\s]+))/g, (m) => {
                 try {
                     const abs = m.startsWith("http") ? m : new URL(m, this.target).href;
                     return this.proxy + "/" + abs;
                 } catch(e) { return m; }
             });
             el.setAttribute("srcset", newVal);
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
          if (!targetUrl.startsWith('http')) targetUrl = 'https://' + targetUrl;
          window.location.href = window.location.origin + '/' + targetUrl;
      }
  </script>
</body>
</html>`;
}
