
/**
 * Optimized Cloudflare Worker Proxy
 * 1. 内存优化：减少 .text() 调用，强化流式转发
 * 2. 稳定性优化：改进注入脚本，防止浏览器端死循环
 * 3. 性能优化：合并 HTMLRewriter 逻辑
 * 4. 功能：CORS 代理 + M3U8 处理 + 随机 IP 伪装
 */

const UNSAFE_HEADERS = [
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-xss-protection",
  "x-content-type-options"
];

function generateRandomIp() {
  return Array.from({ length: 4 }, () => Math.floor(Math.random() * 256)).join('.');
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/") {
      return new Response(getRootHtml(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    // 1. 解析目标 URL
    let actualUrlStr = url.pathname.slice(1);
    try { actualUrlStr = decodeURIComponent(actualUrlStr); } catch (e) {}
    actualUrlStr += url.search + url.hash;

    if (actualUrlStr.startsWith("http") && !actualUrlStr.match(/^https?:\/\//)) {
      actualUrlStr = actualUrlStr.replace(/^(https?):\/+/, "$1://");
    }

    // 处理相对路径回溯
    if (!actualUrlStr.startsWith("http")) {
      const referer = request.headers.get("Referer");
      if (referer) {
        try {
          const refObj = new URL(referer);
          if (refObj.origin === url.origin) {
            let refTarget = decodeURIComponent(refObj.pathname.slice(1));
            if (refTarget.startsWith("http")) {
              actualUrlStr = new URL(url.pathname + url.search, new URL(refTarget).href).href;
            }
          }
        } catch (e) {}
      }
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "*",
          "Access-Control-Allow-Headers": "*"
        }
      });
    }

    let targetUrl;
    try {
      targetUrl = new URL(actualUrlStr);
    } catch (e) {
      return new Response("Invalid URL", { status: 400 });
    }

    // 2. 构建代理请求头
    const newHeaders = new Headers();
    for (const [key, value] of request.headers) {
      const lowKey = key.toLowerCase();
      if (!lowKey.startsWith("cf-") && !lowKey.startsWith("sec-") && lowKey !== "host") {
        newHeaders.set(key, value);
      }
    }

    // IP 随机化
    const randomIp = generateRandomIp();
    newHeaders.set("X-Forwarded-For", randomIp);
    newHeaders.set("X-Real-IP", randomIp);
    newHeaders.set("Host", targetUrl.host);
    
    // 强制设置 UA 防止某些站点屏蔽
    if (!newHeaders.has("User-Agent")) {
      newHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
    }

    // 3. 执行请求
    let response;
    try {
      response = await fetch(actualUrlStr, {
        method: request.method,
        headers: newHeaders,
        body: request.body,
        redirect: "manual"
      });
    } catch (e) {
      return new Response("Fetch Error: " + e.message, { status: 502 });
    }

    // 4. 处理响应
    const responseHeaders = new Headers(response.headers);
    UNSAFE_HEADERS.forEach(h => responseHeaders.delete(h));
    responseHeaders.set("Access-Control-Allow-Origin", "*");

    // 处理重定向
    const loc = responseHeaders.get("Location");
    if (loc) {
      const absLoc = new URL(loc, targetUrl.href).href;
      responseHeaders.set("Location", url.origin + "/" + encodeURIComponent(absLoc));
    }

    const contentType = (responseHeaders.get("Content-Type") || "").toLowerCase();

    // 5. 针对性流式处理
    // M3U8 优化：仅对特定类型进行 text 操作
    if (contentType.includes("mpegurl") || actualUrlStr.includes(".m3u8")) {
      let text = await response.text();
      const baseUrl = actualUrlStr.substring(0, actualUrlStr.lastIndexOf("/") + 1);
      text = text.replace(/^(?!#)(?!\s)(.+)$/gm, (line) => {
        try {
          return url.origin + "/" + new URL(line.trim(), baseUrl).href;
        } catch (e) { return line; }
      });
      return new Response(text, { headers: responseHeaders });
    }

    // HTML 注入优化：使用 HTMLRewriter 的流式处理减少内存占用
    if (contentType.includes("text/html")) {
      return new HTMLRewriter()
        .on("head", {
          element(el) {
            // 极简化的劫持脚本，重点在于判断逻辑，避免死循环
            el.append(`
            <script>
              (function() {
                const P = window.location.origin + '/';
                const B = '${targetUrl.origin}/';
                const wrap = u => {
                  if(!u || typeof u !== 'string' || u.startsWith(P) || u.startsWith('data:') || u.startsWith('blob:')) return u;
                  try { return P + encodeURIComponent(new URL(u, window.location.href).href); } catch(e) { return u; }
                };
                // 劫持 Fetch
                const oF = window.fetch;
                window.fetch = (i, c) => { if(typeof i === 'string') i = wrap(i); return oF(i, c); };
                // 劫持 XHR
                const oO = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(m, u, ...a) { return oO.call(this, m, wrap(u), ...a); };
              })();
            </script>`, { html: true });
          }
        })
        .on("a, img, link, script, video, audio, source, iframe", {
          element(el) {
            const attr = el.tagName === "link" || el.tagName === "a" ? "href" : "src";
            const val = el.getAttribute(attr);
            if (val && !val.startsWith("data:") && !val.startsWith("#")) {
              try {
                const full = new URL(val, targetUrl.href).href;
                el.setAttribute(attr, url.origin + "/" + full);
              } catch (e) {}
            }
          }
        })
        .transform(new Response(response.body, { headers: responseHeaders }));
    }

    // 其他所有资源（JS, CSS, 图片, 视频分片）直接流式转发，不进内存
    return new Response(response.body, {
      status: response.status,
      headers: responseHeaders
    });
  }
};

function getRootHtml() {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Ultra Proxy</title>
  <style>
    body{font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f0f2f5}
    .c{background:#fff;padding:2rem;border-radius:1rem;box-shadow:0 10px 25px rgba(0,0,0,0.05);width:90%;max-width:400px}
    input{width:100%;padding:12px;margin:1rem 0;border:1px solid #ddd;border-radius:6px;box-sizing:border-box}
    button{width:100%;padding:12px;background:#007aff;color:#fff;border:none;border-radius:6px;cursor:pointer;font-weight:600}
  </style></head>
  <body><div class="c"><h3>Proxy Everything</h3><p style="color:#666;font-size:14px">输入完整网址开始无痕访问</p>
  <input type="text" id="u" placeholder="https://..." onkeypress="if(event.key==='Enter')go()"><button onclick="go()">开始浏览</button></div>
  <script>function go(){const v=document.getElementById('u').value;if(v)window.location.href='/'+encodeURIComponent(v)}</script>
  </body></html>`;
}
