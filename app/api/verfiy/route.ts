import { NextResponse } from "next/server";

// Ensure route is dynamic and handles CORS properly
export const dynamic = 'force-dynamic';

function getCorsHeaders(origin: string | null) {
  const allowedOrigin = origin || "*";
  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Credentials": "false",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

/**
 * Preflight handler
 */
export async function OPTIONS(req: Request) {
  const origin = req.headers.get("origin");
  return new NextResponse(null, {
    status: 204,
    headers: getCorsHeaders(origin),
  });
}

/**
 * Verify Turnstile token
 */
export async function POST(req: Request) {
  const origin = req.headers.get("origin");
  const corsHeaders = getCorsHeaders(origin);

  try {
    const { token } = await req.json();

    if (!token) {
      return NextResponse.json(
        { success: false, error: "missing-token" },
        { status: 400, headers: corsHeaders }
      );
    }

    const secret = process.env.CLOUDFLARE_TURNSTILE_SECRET_KEY;

    if (!secret) {
      return NextResponse.json(
        { success: false, error: "server-misconfigured" },
        { status: 500, headers: corsHeaders }
      );
    }

    // Get client IP for better security
    const remoteip =
      req.headers.get("CF-Connecting-IP") ||
      req.headers.get("X-Forwarded-For") ||
      req.headers.get("x-real-ip") ||
      null;

    const formData = new FormData();
    formData.append("secret", secret);
    formData.append("response", token);
    if (remoteip) {
      formData.append("remoteip", remoteip);
    }

    const cfRes = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        body: formData,
      }
    );

    const result = await cfRes.json();

    if (!result.success) {
      console.log("Blocked Turnstile:", result["error-codes"]);
      return NextResponse.json(
        { success: false },
        { status: 403, headers: corsHeaders }
      );
    }

    return NextResponse.json(
      { success: true },
      { status: 200, headers: corsHeaders }
    );

  } catch (err) {
    console.error("Turnstile error", err);
    return NextResponse.json(
      { success: false, error: "internal-error" },
      { status: 500, headers: corsHeaders }
    );
  }
}
