import { NextResponse } from "next/server";

// Cloudflare Turnstile secret key (SERVER ONLY)
const SECRET_KEY = process.env.CLOUDFLARE_TURNSTILE_SECRET_KEY;

async function validateTurnstile(token: string, remoteip: string | null) {
  if (!SECRET_KEY) {
    console.error("Turnstile secret key is not configured");
    return { success: false, "error-codes": ["server-misconfiguration"] };
  }

  const formData = new FormData();
  formData.append("secret", SECRET_KEY);
  formData.append("response", token);

  if (remoteip) {
    formData.append("remoteip", remoteip);
  }

  try {
    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        body: formData,
      }
    );

    const result = await response.json();
    return result;
  } catch (error) {
    console.error("Turnstile validation error:", error);
    return { success: false, "error-codes": ["internal-error"] };
  }
}

export async function POST(req: Request) {
  try {
    // Usage similar to your example handleFormSubmission
    const body = await req.formData();
    const token = body.get("cf-turnstile-response");

    if (!token || typeof token !== "string") {
      return NextResponse.json(
        { success: false, error: "Missing Turnstile token" },
        { status: 400 }
      );
    }

    const ip =
      req.headers.get("CF-Connecting-IP") ||
      req.headers.get("X-Forwarded-For") ||
      req.headers.get("x-real-ip") ||
      "unknown";

    const validation = await validateTurnstile(token, ip);

    if (validation.success) {
      // Token is valid - process the form (you can extend this as needed)
      console.log("Valid submission from:", validation.hostname);
      return NextResponse.json({
        success: true,
        message: "Human verified",
        hostname: validation.hostname,
      });
    } else {
      console.log("Invalid token:", validation["error-codes"]);
      return NextResponse.json(
        {
          success: false,
          error: "Turnstile verification failed",
          details: validation["error-codes"] || [],
        },
        { status: 400 }
      );
    }
  } catch (error) {
    console.error("Turnstile route error:", error);
    return NextResponse.json(
      { success: false, error: "Internal server error" },
      { status: 500 }
    );
  }
}