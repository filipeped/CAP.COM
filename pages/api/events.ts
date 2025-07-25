// ✅ DIGITAL PAISAGISMO CAPI V6.2 - COMPLETO E OTIMIZADO 
// Corrigido: normalização de acentos, arrays para user_data, validação robusta FBP/FBC 

import type { NextApiRequest, NextApiResponse } from "next"; 
import crypto from "crypto"; 
import zlib from "zlib"; 

const PIXEL_ID = "765087775987515"; 
const ACCESS_TOKEN = "EAAQfmxkTTZCcBPEcIiZAy6OKIxlt0ZBQxYHCcVT3pLFZAOR6zr1PjKMOV844YNtdNFp2PRgwkBvhFIYLv5ZBVnltHDRnlZAAZCH8gIZCK0HHs6dR4QpWOUKxKvoaUXvUobAsJZB4c0eraiIzoJFkPeanQ6v7PPzzDqIZB6dniUDyQK6PhwrVPGLmzgPoaDzz9bYwZDZD"; 
const META_URL = `https://graph.facebook.com/v19.0/${PIXEL_ID}/events`; 

// ✅ CORREÇÃO CRÍTICA: Normalização de acentos para nomes brasileiros 
function hashSHA256(value: string) { 
  if (!value || typeof value !== 'string') { 
    console.warn('⚠️ hashSHA256: Valor inválido:', value); 
    return null; 
  } 
  return crypto.createHash("sha256") 
    .update( 
      value 
        .trim() 
        // ✅ CORREÇÃO: Removido .toLowerCase() para preservar fbclid
        .normalize("NFD") 
        .replace(/[\u0300-\u036f]/g, "") // Remove acentos 
    ) 
    .digest("hex"); 
} 

const RATE_LIMIT = 30; 
const rateLimitMap = new Map(); 

function rateLimit(ip: string): boolean { 
  const now = Date.now(); 
  const windowMs = 60000; 
  if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []); 
  const timestamps = rateLimitMap.get(ip)!.filter((t: number) => now - t < windowMs); 
  if (timestamps.length >= RATE_LIMIT) return false; 
  timestamps.push(now); 
  rateLimitMap.set(ip, timestamps); 
  if (rateLimitMap.size > 1000) { 
    const oldestKey = rateLimitMap.keys().next().value; 
    rateLimitMap.delete(oldestKey); 
  } 
  return true; 
} 

// ✅ NOVA FUNÇÃO: Processamento robusto do FBC 
const processFbc = (fbcRaw: string | undefined): string | null => { 
  if (!fbcRaw || typeof fbcRaw !== 'string') { 
    console.log('🔍 FBC Debug: Valor ausente ou inválido:', fbcRaw); 
    return null; 
  } 

  // Caso 1: FBC já no formato correto (fb.1.timestamp.fbclid) 
  if (fbcRaw.startsWith('fb.1.') && fbcRaw.split('.').length === 4) { 
    console.log('✅ FBC Debug: Formato fb.1 válido:', fbcRaw.substring(0, 20) + '...'); 
    return fbcRaw; 
  } 

  // Caso 2: fbclid puro (sem prefixo) 
  if (fbcRaw.length > 10 && !fbcRaw.includes('.') && !fbcRaw.startsWith('fb.')) { 
    const formattedFbc = `fb.1.${Date.now()}.${fbcRaw}`; 
    console.log('🔧 FBC Debug: fbclid convertido:', { 
      original: fbcRaw.substring(0, 15) + '...', 
      formatted: formattedFbc.substring(0, 30) + '...' 
    }); 
    return formattedFbc; 
  } 

  // Caso 3: fbclid com prefixo "fbclid=" 
  if (fbcRaw.startsWith('fbclid=')) { 
    const cleanFbclid = fbcRaw.replace('fbclid=', ''); 
    const formattedFbc = `fb.1.${Date.now()}.${cleanFbclid}`; 
    console.log('🔧 FBC Debug: fbclid= convertido:', { 
      original: fbcRaw.substring(0, 15) + '...', 
      formatted: formattedFbc.substring(0, 30) + '...' 
    }); 
    return formattedFbc; 
  } 

  console.warn('⚠️ FBC Debug: Formato não reconhecido:', fbcRaw.substring(0, 20) + '...'); 
  return null; 
}; 

export default async function handler(req: NextApiRequest, res: NextApiResponse) { 
  const startTime = Date.now(); 
  const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown"; 
  const userAgent = req.headers["user-agent"] || ""; 
  const origin = req.headers.origin; 

  const ALLOWED_ORIGINS = [ 
    "https://www.digitalpaisagismo.com", 
    "https://digitalpaisagismo.com", // <-- Adicionado domínio sem www 
    "https://cap.digitalpaisagismo.com", 
    "https://atendimento.digitalpaisagismo.com", 
    "https://projeto.digitalpaisagismo.com", 
    "https://www.projeto.digitalpaisagismo.com", 
    "http://localhost:3000",
  ]; 

  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGINS.includes(origin!) ? origin! : "https://www.digitalpaisagismo.com"); 
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS"); 
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With"); 
  res.setHeader("Access-Control-Allow-Credentials", "true"); 
  res.setHeader("X-Content-Type-Options", "nosniff"); 
  res.setHeader("X-Frame-Options", "DENY"); 
  res.setHeader("Referrer-Policy", "no-referrer"); 
  res.setHeader("X-Robots-Tag", "noindex, nofollow"); 
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains"); 

  if (req.method === "OPTIONS") return res.status(200).end(); 
  if (req.method !== "POST") return res.status(405).json({ error: "Method Not Allowed" }); 
  if (!rateLimit(ip)) return res.status(429).json({ error: "Limite de requisições excedido", retry_after: 60 }); 

  try { 
    if (!req.body?.data || !Array.isArray(req.body.data)) { 
      return res.status(400).json({ error: "Payload inválido - campo 'data' obrigatório" }); 
    } 

    const enrichedData = req.body.data.map((event: any) => { 
      const sessionId = event.session_id || ""; 
      const externalId = sessionId ? hashSHA256(sessionId) : ""; 
      const eventId = event.event_id || `evt_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`; 
      const eventName = event.event_name || "Lead"; 
      const eventSourceUrl = event.event_source_url || origin || req.headers.referer || "https://www.digitalpaisagismo.com"; 
      const eventTime = event.event_time || Math.floor(Date.now() / 1000); 
      const actionSource = event.action_source || "website"; 

      const email = event.user_data?.email || ""; 
      const phone = event.user_data?.phone || ""; 
      const first_name = event.user_data?.first_name || ""; 
      const last_name = event.user_data?.last_name || ""; 

      // ✅ CORREÇÃO: Validação robusta do value para eventos de conversão 
      let customData = { ...event.custom_data }; 

      if (eventName === 'Lead' || eventName === 'Purchase' || eventName === 'CompleteRegistration') { 
        const rawValue = event.custom_data?.value; 
        const parsedValue = typeof rawValue === "string" ? Number(rawValue) : rawValue; 

        if (!isNaN(parsedValue) && parsedValue > 0) { 
          customData.value = parsedValue; 
          customData.currency = event.custom_data?.currency || "BRL"; 
        } else { 
          // ✅ CORREÇÃO: Valor padrão para Lead 
          customData.value = eventName === 'Lead' ? 5000 : 1000; 
          customData.currency = "BRL"; 
        } 
      } else { 
        // ✅ CORREÇÃO: Remove value/currency de eventos comportamentais 
        delete customData.value; 
        delete customData.currency; 
      } 

      // ✅ CORREÇÃO: Hash apenas se dados válidos 
      const hashedEmail = email ? hashSHA256(email) : null; 
      const hashedPhone = phone ? hashSHA256(phone.replace(/\D/g, "")) : null; 
      const hashedFirstName = first_name ? hashSHA256(first_name) : null; 
      const hashedLastName = last_name ? hashSHA256(last_name) : null; 

      // ✅ PROCESSAMENTO MELHORADO DO FBC 
      const processedFbc = processFbc(event.user_data?.fbc); 

      return { 
        event_name: eventName, 
        event_id: eventId, 
        event_time: eventTime, 
        event_source_url: eventSourceUrl, 
        action_source: actionSource, 
        custom_data: customData, 
        user_data: { 
          // ✅ CORREÇÃO: external_id apenas se válido e sempre array 
          ...(externalId && { external_id: [externalId] }), 
          // ✅ CORREÇÃO: PII apenas se válido e sempre array 
          ...(hashedEmail && { em: [hashedEmail] }), 
          ...(hashedPhone && { ph: [hashedPhone] }), 
          ...(hashedFirstName && { fn: [hashedFirstName] }), 
          ...(hashedLastName && { ln: [hashedLastName] }), 
          client_ip_address: ip, 
          client_user_agent: userAgent, 
          // ✅ CORREÇÃO: FBP apenas se válido 
          ...(typeof event.user_data?.fbp === "string" && event.user_data.fbp.startsWith("fb.") && { fbp: event.user_data.fbp }), 
          // ✅ CORREÇÃO FBC: Usar função dedicada 
          ...(processedFbc && { fbc: processedFbc }) 
        } 
      }; 
    }); 

    const payload = { data: enrichedData }; 
    const shouldCompress = Buffer.byteLength(JSON.stringify(payload)) > 2048; 
    const body = shouldCompress ? zlib.gzipSync(JSON.stringify(payload)) : JSON.stringify(payload); 
    const headers = { 
      "Content-Type": "application/json", 
      "Connection": "keep-alive", 
      "User-Agent": "DigitalPaisagismo-CAPI-Proxy/1.0", 
      ...(shouldCompress && { "Content-Encoding": "gzip" }) 
    }; 

    const controller = new AbortController(); 
    const timeout = setTimeout(() => controller.abort(), 8000);

    console.log("🔄 Enviando evento para Meta CAPI:", { 
      events: enrichedData.length, 
      event_names: enrichedData.map(e => e.event_name), 
      has_pii: enrichedData.some(e => e.user_data.em || e.user_data.ph || e.user_data.fn || e.user_data.ln), 
      // ✅ ADICIONADO: Debug de FBC 
      fbc_status: enrichedData.map(e => ({ 
        event_id: e.event_id.substring(0, 10) + '...', 
        has_fbc: !!e.user_data.fbc, 
        fbc_preview: e.user_data.fbc ? e.user_data.fbc.substring(0, 25) + '...' : 'null' 
      })) 
    }); 

    const response = await fetch(`${META_URL}?access_token=${ACCESS_TOKEN}`, { 
      method: "POST", 
      headers, 
      body, 
      signal: controller.signal 
    }); 

    clearTimeout(timeout); 
    const data = await response.json(); 
    const responseTime = Date.now() - startTime; 

    if (!response.ok) { 
      console.error("❌ Erro da Meta CAPI:", { 
        status: response.status, 
        data, 
        events: enrichedData.length 
      }); 

      return res.status(response.status).json({ 
        error: "Erro da Meta", 
        details: data, 
        processing_time_ms: responseTime 
      }); 
    } 

    console.log("✅ Evento enviado com sucesso para Meta CAPI:", { 
      events_processed: enrichedData.length, 
      processing_time_ms: responseTime, 
      compression_used: shouldCompress 
    }); 

    res.status(200).json({ 
      ...data, 
      proxy_metadata: { 
        processing_time_ms: responseTime, 
        events_processed: enrichedData.length, 
        compression_used: shouldCompress, 
        timestamp: new Date().toISOString(), 
        pii_processed: enrichedData.some(e => e.user_data.em || e.user_data.ph || e.user_data.fn || e.user_data.ln) 
      } 
    }); 

  } catch (error: any) { 
    console.error("❌ Erro no Proxy CAPI:", error); 
    if (error.name === "AbortError") { 
      return res.status(408).json({ error: "Timeout ao enviar evento para a Meta", timeout_ms: 8000 }); 
    } 
    res.status(500).json({ error: "Erro interno no servidor CAPI." }); 
  } 
}
