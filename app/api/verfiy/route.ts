import { NextResponse } from "next/server";

/**
 * CORS headers
 */
const corsHeaders = {
  "Access-Control-Allow-Origin": "*", // you can restrict to your Webflow domain later
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

/**
 * Handle preflight (CORS)
 */
export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: corsHeaders,
  });
}

/**
 * Verify Turnstile token
 */
export async function POST(req: Request) {
  try {
    const body = await req.json();
    const token = body.token;

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

    const formData = new FormData();
    formData.append("secret", secret);
    formData.append("response", token);

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
        {
          success: false,
          errors: result["error-codes"] || [],
        },
        { status: 403, headers: corsHeaders }
      );
    }

    return NextResponse.json(
      { success: true },
      { status: 200, headers: corsHeaders }
    );

  } catch (err) {
    console.error("Turnstile verification error", err);
    return NextResponse.json(
      { success: false, error: "internal-error" },
      { status: 500, headers: corsHeaders }
    );
  }
}
