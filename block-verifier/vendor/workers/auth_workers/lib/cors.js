// workers/lib/cors.js

export function createCORSResponse(response, status = 200) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*", // 必要なら origin に変更
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With, X-Api-Secret",
      "Access-Control-Allow-Credentials": "true",
      "Vary": "Origin"
    };

    if (response instanceof Response) {
      const newHeaders = new Headers(response.headers);
      Object.keys(corsHeaders).forEach(key => {
        newHeaders.set(key, corsHeaders[key]);
      });

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders
      });
    }

    const body = JSON.stringify(response);
    const headers = new Headers({
      "Content-Type": "application/json",
      ...corsHeaders
    });

    return new Response(body, { status, headers });
  }
