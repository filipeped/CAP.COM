// /pages/api/events.ts
// ✅ DIGITAL PAISAGISMO CAPI V8.2 - EVENT_ID OBRIGATÓRIO + IPv6 OTIMIZADO + DEDUPLICAÇÃO

import type { NextApiRequest, NextApiResponse } from "next";
import zlib from "zlib";

const PIXEL_ID = "765087775987515";
const ACCESS_TOKEN =
  "EAAQfmxkTTZCcBPHGbA2ojC29bVbNPa6GM3nxMxsZC29ijBmuyexVifaGnrjFZBZBS6LEkaR29X3tc5TWn4SHHffeXiPvexZAYKP5mTMoYGx5AoVYaluaqBTtiKIjWALxuMZAPVcBk1PuYCb0nJfhpzAezh018LU3cT45vuEflMicoQEHHk3H5YKNVAPaUZC6yzhcQZDZD";
const META_URL = `https://graph.facebook.com/v19.0/${PIXEL_ID}/events`;

// ✅ DEDUPLICAÇÃO
const eventCache = new Map<string, number>();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutos
const MAX_CACHE_SIZE = 10000;

function isDuplicateEvent(eventId: string): boolean {
  const now = Date.now();

  // limpa expirados
  let cleaned = 0;
  eventCache.forEach((ts, id) => {
    if (now - ts > CACHE_TTL) {
      eventCache.delete(id);
      cleaned++;
    }
  });
  if (cleaned > 0) console.log(`🧹 Cache limpo: ${cleaned} eventos expirados`);

  if (eventCache.has(eventId)) {
    console.warn("🚫 Evento duplicado bloqueado:", eventId);
    return true;
  }

  if (eventCache.size >= MAX_CACHE_SIZE) {
    const oldest = eventCache.keys().next();
    if (!oldest.done) eventCache.delete(oldest.value);
  }

  eventCache.set(eventId, now);
  return false;
}

// ✅ IP inteligente
function getClientIP(
  req: NextApiRequest
): { ip: string; type: "IPv4" | "IPv6" | "unknown" } {
  const ipSources = [
    req.headers["cf-connecting-ip"],
    req.headers["x-real-ip"],
    req.headers["x-forwarded-for"],
    req.socket?.remoteAddress,
  ];

  const candidateIPs: string[] = [];
  ipSources.forEach((s) => {
    if (!s) return;
    if (typeof s === "string") {
      candidateIPs.push(...s.split(",").map((ip) => ip.trim()));
    }
  });

  const ipv4 = candidateIPs.find((ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip));
  const ipv6 = candidateIPs.find((ip) => ip.includes(":"));

  if (ipv6) return { ip: ipv6, type: "IPv6" };
  if (ipv4) return { ip: ipv4, type: "IPv4" };
  return { ip: candidateIPs[0] || "unknown", type: "unknown" };
}

// ✅ FBC
function processFbc(fbc: string): string | null {
  if (!fbc) return null;
  const trimmed = fbc.trim();

  const full = /^fb\.1\.[0-9]+\.[A-Za-z0-9_-]+$/;
  if (full.test(trimmed)) return trimmed;

  const pure = /^[A-Za-z0-9_-]+$/;
  if (pure.test(trimmed)) {
    return `fb.1.${Math.floor(Date.now() / 1000)}.${trimmed}`;
  }

  if (trimmed.startsWith("fbclid=")) {
    const fbclid = trimmed.slice(7);
    if (pure.test(fbclid)) {
      return `fb.1.${Math.floor(Date.now() / 1000)}.${fbclid}`;
    }
  }

  return null;
}

// ✅ Rate limit
const RATE_LIMIT = 30;
const rateMap = new Map<string, number[]>();
function rateLimit(ip: string): boolean {
  const now = Date.now();
  const win = 60000;
  if (!rateMap.has(ip)) rateMap.set(ip, []);
  const ts = (rateMap.get(ip) || []).filter((t) => now - t < win);
  if (ts.length >= RATE_LIMIT) return false;
  ts.push(now);
  rateMap.set(ip, ts);
  return true;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { ip, type: ipType } = getClientIP(req);
  const userAgent = req.headers["user-agent"] || "";
  const origin = (req.headers.origin as string) || "";

  const ALLOWED = [
    "https://www.digitalpaisagismo.com",
    "https://digitalpaisagismo.com",
    "https://cap.digitalpaisagismo.com",
    "http://localhost:3000",
  ];

  res.setHeader("Access-Control-Allow-Origin", ALLOWED.includes(origin) ? origin : ALLOWED[0]);
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method Not Allowed" });
  if (!rateLimit(ip)) return res.status(429).json({ error: "Limite excedido" });

  try {
    if (!req.body?.data || !Array.isArray(req.body.data)) {
      return res.status(400).json({ error: "Payload inválido - campo data obrigatório" });
    }

    // 🔴 OBRIGA event_id
    for (const ev of req.body.data) {
      if (!ev.event_id || typeof ev.event_id !== "string") {
        return res.status(400).json({ error: "event_id obrigatório para deduplicação Browser+CAPI" });
      }
    }

    // Deduplicação
    const originalCount = req.body.data.length;
    const filtered = req.body.data.filter((ev: any) => !isDuplicateEvent(ev.event_id));
    const blocked = originalCount - filtered.length;

    if (filtered.length === 0) {
      return res.status(200).json({ message: "Todos duplicados", blocked, cache: eventCache.size });
    }

    const enriched = filtered.map((ev: any) => {
      const userData: any = {
        ...(ev.user_data?.external_id && { external_id: ev.user_data.external_id }),
        client_ip_address: ip,
        client_user_agent: userAgent,
      };

      if (ev.user_data?.fbp) userData.fbp = ev.user_data.fbp;
      if (ev.user_data?.fbc) {
        const p = processFbc(ev.user_data.fbc);
        if (p) userData.fbc = p;
      }
      if (ev.user_data?.country) userData.country = ev.user_data.country.toLowerCase();

      return {
        event_name: ev.event_name || "Lead",
        event_id: ev.event_id,
        event_time: ev.event_time || Math.floor(Date.now() / 1000),
        event_source_url: ev.event_source_url || origin,
        action_source: ev.action_source || "website",
        custom_data: ev.custom_data || {},
        user_data: userData,
      };
    });

    const payload = JSON.stringify({ data: enriched });
    const compress = Buffer.byteLength(payload) > 2048;
    const body = compress ? zlib.gzipSync(payload) : payload;

    const response = await fetch(`${META_URL}?access_token=${ACCESS_TOKEN}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(compress && { "Content-Encoding": "gzip" }),
      },
      body: body as any,
    });

    const data = await response.json();
    if (!response.ok) {
      return res.status(response.status).json({ error: "Erro Meta", details: data });
    }

    return res.status(200).json({
      ...data,
      deduplication: { original: originalCount, processed: enriched.length, blocked },
      ip_info: { ip, type: ipType },
    });
  } catch (e: any) {
    if (e.name === "AbortError") {
      return res.status(408).json({ error: "Timeout Meta" });
    }
    return res.status(500).json({ error: "Erro interno CAPI" });
  }
}
