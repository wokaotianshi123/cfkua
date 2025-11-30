// _worker.js

// 常量定义
const ASSET_EXTENSIONS = new Set([
  "js", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "eot", "mp4", "webm", "mp3"
]);

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. 访问根目录，返回 UI 界面
    if (url.pathname === "/") {
      return new Response(getRootHtml(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    // 2. 解析目标 URL
    // 逻辑：路径即为目标URL。例如 proxy.com/https://google.com
    let actualUrlStr = url.pathname.slice(1) + url.search + url.hash;

    // 3. 特殊情况处理：处理浏览器发出的相对路径请求（如 /favicon.ico）
    // 如果用户访问 proxy.com/https://site.com，HTML里有个 <img src="/logo.png">
    // 浏览器会请求 proxy.com/logo.png。我们需要尝试通过 Referer 找回原来的目标。
    if (!actualUrlStr.startsWith("http")) {
      const referer = request.headers.get("Referer");
      if (referer) {
        try {
          const refererUrl = new URL(referer);
          // 检查 Referer 是否也是咱们的代理
          if (refererUrl.origin === url.origin && refererUrl.pathname !== "/") {
            // 提取 Referer 中的目标根路径
            // refererPath: /https://target.com/page/1
            const refererTarget = refererUrl.pathname.slice(1);
            const targetBase = new URL(refererTarget).origin;
            actualUrlStr = targetBase + "/" + actualUrlStr;
          }
        } catch (e) {
          // Referer 解析失败，忽略
        }
      }
    }

    // 兜底：如果还是没有协议，尝试加 https
    if (!actualUrlStr.startsWith("http://") && !actualUrlStr.startsWith("https://")) {
       // 如果看起来像域名，加 https，否则可能是一个无法处理的资源
       if (actualUrlStr.includes(".")) {
         actualUrlStr = "https://" + actualUrlStr;
       } else {
         return new Response("Invalid URL", { status: 400 });
       }
    }

    // 4. 发起代理请求
    try {
      // 过滤掉 Cloudflare 自身的 headers 和不安全的 headers
      const newHeaders = new Headers();
      for (const [key, value] of request.headers) {
        if (!key.startsWith("cf-") && key.toLowerCase() !== "host") {
          newHeaders.set(key, value);
        }
      }
      
      // 构造新请求
      const modifiedRequest = new Request(actualUrlStr, {
        headers: newHeaders,
        method: request.method,
        body: request.body,
        redirect: "manual" // 手动处理重定向
      });

      const response = await fetch(modifiedRequest);
      
      // 5. 处理响应
      let newResponse;
      const contentType = response.headers.get("Content-Type") || "";

      // 情况 A: 重定向 (3xx)
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get("Location");
        if (location) {
          // 将重定向地址重写回代理地址
          const resolvedLocation = new URL(location, actualUrlStr).toString();
          const proxyLocation = url.origin + "/" + resolvedLocation;
          newResponse = new Response(response.body, response);
          newResponse.headers.set("Location", proxyLocation);
        } else {
          newResponse = new Response(response.body, response);
        }
      }
      // 情况 B: HTML 内容 (使用 HTMLRewriter 重写链接)
      else if (contentType.includes("text/html")) {
        const rewriter = new HTMLRewriter()
          .on("a", new AttributeRewriter("href", url.origin, actualUrlStr))
          .on("img", new AttributeRewriter("src", url.origin, actualUrlStr))
          .on("link", new AttributeRewriter("href", url.origin, actualUrlStr))
          .on("script", new AttributeRewriter("src", url.origin, actualUrlStr))
          .on("form", new AttributeRewriter("action", url.origin, actualUrlStr))
          .on("iframe", new AttributeRewriter("src", url.origin, actualUrlStr))
          .on("video", new AttributeRewriter("src", url.origin, actualUrlStr))
          .on("audio", new AttributeRewriter("src", url.origin, actualUrlStr))
          .on("source", new AttributeRewriter("src", url.origin, actualUrlStr))
          .on("object", new AttributeRewriter("data", url.origin, actualUrlStr));

        newResponse = rewriter.transform(response);
      }
      // 情况 C: 其他内容 (直接透传)
      else {
        newResponse = new Response(response.body, response);
      }

      // 6. 添加必要的 CORS 和 缓存控制
      newResponse.headers.set("Access-Control-Allow-Origin", "*");
      newResponse.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
      newResponse.headers.set("Access-Control-Allow-Headers", "*");
      // 为了防止浏览器缓存错误的重写结果，建议不缓存 HTML，但静态资源可以缓存
      if (contentType.includes("text/html")) {
        newResponse.headers.set("Cache-Control", "no-cache, no-store, must-revalidate");
      }

      return newResponse;

    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
      });
    }
  }
};

/**
 * HTMLRewriter 的处理类
 * 用于将 HTML 中的相对路径/绝对路径转换为代理路径
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
      try {
        // 忽略特殊协议
        if (value.startsWith("data:") || value.startsWith("#") || value.startsWith("mailto:") || value.startsWith("javascript:")) {
          return;
        }

        // 解析完整的目标 URL (处理 ./, ../, / 等相对路径)
        const resolvedUrl = new URL(value, this.currentTargetUrl).toString();
        
        // 构造代理 URL: proxy.com/https://target.com/path
        const proxiedUrl = this.proxyOrigin + "/" + resolvedUrl;
        
        element.setAttribute(this.attributeName, proxiedUrl);
      } catch (e) {
        // 解析失败则保留原样
      }
    }
    
    // 特殊处理 srcset (用于响应式图片)
    if (element.tagName === 'img' && element.hasAttribute('srcset')) {
      const srcset = element.getAttribute('srcset');
      const newSrcset = srcset.split(',').map(srcDef => {
        const [src, width] = srcDef.trim().split(/\s+/);
        try {
           const resolvedSrc = new URL(src, this.currentTargetUrl).toString();
           return `${this.proxyOrigin}/${resolvedSrc} ${width || ''}`;
        } catch (e) { return srcDef; }
      }).join(', ');
      element.setAttribute('srcset', newSrcset);
    }
  }
}

/**
 * UI 页面代码 (保持了你的原版风格，增强了 Materialize 引用)
 */
function getRootHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>Proxy Everything</title>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
      body { display: flex; min-height: 100vh; flex-direction: column; background: #f5f5f5; }
      main { flex: 1 0 auto; display: flex; align-items: center; justify-content: center; }
      .card { min-width: 350px; padding: 20px; }
      .input-field input:focus + label { color: #26a69a !important; }
      .input-field input:focus { border-bottom: 1px solid #26a69a !important; box-shadow: 0 1px 0 0 #26a69a !important; }
  </style>
</head>
<body>
  <main>
      <div class="container">
          <div class="row">
              <div class="col s12 m8 offset-m2 l6 offset-l3">
                  <div class="card hoverable">
                      <div class="card-content">
                          <span class="card-title center-align"><i class="material-icons left">public</i>Proxy Everything</span>
                          <p class="center-align grey-text" style="margin-bottom: 20px;">输入完整 URL (如 https://google.com)</p>
                          <form onsubmit="handleSubmit(event)">
                              <div class="input-field">
                                  <input type="text" id="url" required placeholder="https://example.com">
                                  <label for="url">目标地址</label>
                              </div>
                              <button type="submit" class="btn waves-effect waves-light teal lighten-1 w-100" style="width:100%">
                                  访问 <i class="material-icons right">send</i>
                              </button>
                          </form>
                      </div>
                  </div>
              </div>
          </div>
      </div>
  </main>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js"></script>
  <script>
      function handleSubmit(e) {
          e.preventDefault();
          let url = document.getElementById('url').value.trim();
          if (!url.startsWith('http')) url = 'https://' + url;
          window.location.href = window.location.origin + '/' + url;
      }
  </script>
</body>
</html>`;
}
