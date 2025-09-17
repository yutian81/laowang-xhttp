const UPSTREAM_URL = 'https://xxxxx.deno.dev'; // 此处替换为deno项目地址
const UPSTREAM_HOSTNAME = new URL(UPSTREAM_URL).hostname;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const targetUrl = new URL(url.pathname + url.search, UPSTREAM_URL);
    const newRequest = new Request(targetUrl, request);

    newRequest.headers.set('Host', UPSTREAM_HOSTNAME);
    newRequest.headers.set('X-Forwarded-Host', url.hostname);

    try {
      const response = await fetch(newRequest);
      const newResponse = new Response(response.body, response);
      newResponse.headers.delete('X-Content-Type-Options');
      return newResponse;
    } catch (e) {
      return new Response('上游服务不可用', { status: 503 });
    }
  },
};
