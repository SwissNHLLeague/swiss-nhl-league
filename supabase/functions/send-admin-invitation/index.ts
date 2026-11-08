
import { createClient } from "npm:@supabase/supabase-js@2";

const origin = "https://swissnhlleague.github.io";

const headers = {
  "Access-Control-Allow-Origin": origin,
  "Access-Control-Allow-Headers":
    "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};

function reply(message: object, status = 200) {
  return new Response(JSON.stringify(message), {
    status,
    headers,
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers,
    });
  }

  if (req.method !== "POST") {
    return reply({ error: "Methode nicht erlaubt" }, 405);
  }

  try {
    const url = Deno.env.get("SUPABASE_URL");
    const key =
      Deno.env.get("SUPABASE_ANON_KEY") ??
      Deno.env.get("SUPABASE_PUBLISHABLE_KEY");

    if (!url || !key) {
      return reply({
        error: "Serverkonfiguration fehlt",
      }, 503);
    }

    const authorization =
      req.headers.get("Authorization") ?? "";

    if (!authorization.startsWith("Bearer ")) {
      return reply({
        error: "Anmeldung erforderlich",
      }, 401);
    }

    const client = createClient(url, key, {
      global: {
        headers: { Authorization: authorization },
      },
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });

    const { data, error } = await client.auth.getUser(
      authorization.slice(7)
    );

    if (error || !data.user) {
      return reply({
        error: "Ungültige Anmeldung",
      }, 401);
    }

    const { data: admin, error: adminError } =
      await client
        .from("admin_users")
        .select("admin_role")
        .eq("user_id", data.user.id)
        .maybeSingle();

    if (
      adminError ||
      !admin ||
      admin.admin_role !== "owner"
    ) {
      return reply({
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

    if (
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      return reply({
        error: "Ungültige E-Mail-Adresse",
      }, 400);
    }

    if (![
      "league_admin",
      "moderator",
      "stats_manager",
    ].includes(role)) {
      return reply({
        error: "Ungültige Rolle",
      }, 400);
    }

    // Sicherer Testbetrieb:
    // Keine Datenbankänderung.
    // Keine Einladung erstellen.
    // Keine E-Mail versenden.
    // Keine Einladungstokens erzeugen.

    return reply({
      status: "test_ready",
      message:
        "Einladungsdaten erfolgreich geprüft. Versand deaktiviert.",
    });

  } catch (error) {
    console.error("Invitation test error", error);

    return reply({
      error: "Interner Serverfehler",
    }, 500);
  }
});
