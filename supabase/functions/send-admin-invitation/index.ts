
import { createClient } from "npm:@supabase/supabase-js@2";

const allowedOrigin =
  "https://swissnhlleague.github.io";

const corsHeaders = {
  "Access-Control-Allow-Origin": allowedOrigin,
  "Access-Control-Allow-Headers":
    "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};

function respond(
  body: Record<string, unknown>,
  status = 200
) {
  return new Response(JSON.stringify(body), {
    status,
    headers: corsHeaders,
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders,
    });
  }

  if (req.method !== "POST") {
    return respond({ error: "Methode nicht erlaubt" }, 405);
  }

  try {
    const url = Deno.env.get("SUPABASE_URL");
    const key = Deno.env.get("SUPABASE_ANON_KEY")
      ?? Deno.env.get("SUPABASE_PUBLISHABLE_KEY");
    const resendKey = Deno.env.get("RESEND_API_KEY");
    const sender = Deno.env.get("RESEND_FROM_EMAIL");

    if (!url || !key || !resendKey || !sender) {
      return respond({
        error: "Serverkonfiguration unvollständig",
      }, 503);
    }

    const authHeader =
      req.headers.get("Authorization") ?? "";

    if (!authHeader.startsWith("Bearer ")) {
      return respond({
        error: "Anmeldung erforderlich",
      }, 401);
    }

    const client = createClient(url, key, {
      global: {
        headers: {
          Authorization: authHeader,
        },
      },
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });

    const token = authHeader.slice(7);

    const { data: authData, error: authError } =
      await client.auth.getUser(token);

    if (authError || !authData.user) {
      return respond({
        error: "Ungültige Anmeldung",
      }, 401);
    }

    const { data: admin, error: adminError } =
      await client
        .from("admin_users")
        .select("admin_role")
        .eq("user_id", authData.user.id)
        .maybeSingle();

    if (
      adminError ||
      !admin ||
      admin.admin_role !== "owner"
    ) {
      return respond({
        error: "Keine Berechtigung",
      }, 403);
    }

    const body = await req.json().catch(() => null);

    const email =
      typeof body?.email === "string"
        ? body.email.trim().toLowerCase()
        : "";

    const role =
      typeof body?.role === "string"
        ? body.role
        : "";

    const allowedRoles = [
      "league_admin",
      "moderator",
      "stats_manager",
    ];

    if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      email.length > 254 ||
      !allowedRoles.includes(role)
    ) {
      return respond({
        error: "Ungültige Einladungsdaten",
      }, 400);
    }

    // Bestehende sichere Datenbankfunktion verwenden.
    const { data, error } = await client.rpc(
      "admin_create_invitation_token",
      {
        p_email: email,
        p_role: role,
      }
    );

    if (error) {
      console.error("Invitation RPC failed", error.code);
      return respond({
        error: "Einladung konnte nicht erstellt werden",
      }, 400);
    }

    // Nur bekannte Rückgabeformate akzeptieren.
    let result: unknown = data;

    if (typeof result === "string") {
      try {
        result = JSON.parse(result);
      } catch {
        result = { token: result };
      }
    }

    const record =
      result && typeof result === "object" &&
      !Array.isArray(result)
        ? result as Record<string, unknown>
        : null;

    const invitationToken =
      typeof record?.token === "string"
        ? record.token
        : null;

    if (
      !invitationToken ||
      !/^[a-fA-F0-9]{64}$/.test(invitationToken)
    ) {
      return respond({
        error:
          "Einladungsformat muss zuerst geprüft werden",
      }, 503);
    }

    // Noch kein Versand:
    // Zuerst Rückgabeformat, Annahmeseite
    // und Absenderdomain sicher bestätigen.
    return respond({
      status: "prepared",
      message:
        "Einladung vorbereitet. Versand noch nicht freigeschaltet.",
    });

  } catch (error) {
    console.error("Invitation function error", error);
    return respond({
      error: "Interner Serverfehler",
    }, 500);
  }
});
