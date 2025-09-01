// ✅ DIGITAL PAISAGISMO CAPI V8.0 - IPv6 OTIMIZADO + DEDUPLICAÇÃO
// Removido: normalização de acentos e eventos de vídeo
// Adicionado: detecção inteligente IPv6 com fallback IPv4
// Adicionado: sistema de deduplicação de eventos

import type { NextApiRequest, NextApiResponse } from "next";
import crypto from "crypto";
import zlib from "zlib";

const PIXEL_ID = "765087775987515";
const ACCESS_TOKEN = "EAAQfmxkTTZCcBPJy7KylZA9vH9GZBPCXRJX2b57Be1065yvFoOzSfBzRZCFnHzM62ZC2zmKp3sLuHpaZA0BPOTF5ellSuJcG10d41TD3PX4Fw1XcZAUSmQ0cvkF1rbDAfUdChGOpwZBdmgKnyMpMipZCfYyUXaHsZB5eNayraeEI8WQ7G3FuaGdU4ZCoTX2SAuoNwZDZD";
const META_URL = `https://graph.facebook.com/v19.0/${PIXEL_ID}/events`;

// ✅ SISTEMA DE DEDUPLICAÇÃO
const eventCache = new Map<string, number>();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutos
const MAX_CACHE_SIZE = 10000; // Limite de eventos no cache

function isDuplicateEvent(eventId: string): boolean {
  const now = Date.now();
  
  // Limpeza automática de eventos expirados
  let cleanedCount = 0;
  for (const [id, timestamp] of eventCache.entries()) {
    if (now - timestamp > CACHE_TTL) {
      eventCache.delete(id);
      cleanedCount++;
    }
  }
  
  if (cleanedCount > 0) {
    console.log(`🧹 Cache limpo: ${cleanedCount} eventos expirados removidos`);
  }
  
  // Verificar se é duplicata
  if (eventCache.has(eventId)) {
    console.warn('🚫 Evento duplicado bloqueado:', eventId);
    return true;
  }
  
  // Controle de tamanho do cache
  if (eventCache.size >= MAX_CACHE_SIZE) {
    const oldestKey = eventCache.keys().next().value;
    eventCache.delete(oldestKey);
    console.log('🗑️ Cache cheio: evento mais antigo removido');
  }
  
  // Adicionar ao cache
  eventCache.set(eventId, now);
  console.log('✅ Evento adicionado ao cache de deduplicação:', eventId);
  return false;
}

// ✅ SIMPLIFICADO: Hash SHA256 sem normalização de acentos
function hashSHA256(value: string): string | null {
  if (!value || typeof value !== 'string') {
    console.warn('⚠️ hashSHA256: Valor inválido:', value);
    return null;
  }
  return crypto.createHash("sha256")
    .update(value.trim())
    .digest("hex");
}

// ✅ IPv6 INTELIGENTE: Detecção e validação de IP com prioridade IPv6
function getClientIP(req: NextApiRequest): { ip: string; type: 'IPv4' | 'IPv6' | 'unknown' } {
  // ... existing code ...
  // Fontes de IP em ordem de prioridade
  const ipSources = [
    req.headers['cf-connecting-ip'], // Cloudflare
    req.headers['x-real-ip'], // Nginx
    req.headers['x-forwarded-for'], // Load balancers
    req.headers['x-client-ip'], // Apache
    req.headers['x-cluster-client-ip'], // Cluster
    req.socket.remoteAddress // Direto do socket
  ];

  const candidateIPs: string[] = [];
  
  // Coletar todos os IPs candidatos
  for (const source of ipSources) {
    if (source) {
      if (typeof source === 'string') {
        // Para x-forwarded-for, pode ter múltiplos IPs separados por vírgula
        const ips = source.split(',').map(ip => ip.trim());
        candidateIPs.push(...ips);
      }
    }
  }

  // Função para validar IPv4
  function isValidIPv4(ip: string): boolean {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(ip);
  }

  // Função para validar IPv6
  function isValidIPv6(ip: string): boolean {
    // Remove colchetes se presentes [::1] -> ::1
    const cleanIP = ip.replace(/^\[|\]$/g, '');
    
    // Regex aprimorado para IPv6
    const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
    return ipv6Regex.test(cleanIP);
  }

  // Função para verificar se é IP privado/local
  function isPrivateIP(ip: string): boolean {
    if (isValidIPv4(ip)) {
      const parts = ip.split('.').map(Number);
      return (
        parts[0] === 10 || // 10.0.0.0/8
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || // 172.16.0.0/12
        (parts[0] === 192 && parts[1] === 168) || // 192.168.0.0/16
        parts[0] === 127 // 127.0.0.0/8 (localhost)
      );
    }
    
    if (isValidIPv6(ip)) {
      const cleanIP = ip.replace(/^\[|\]$/g, '');
      return (
        cleanIP === '::1' || // localhost
        cleanIP.startsWith('fe80:') || // link-local
        cleanIP.startsWith('fc00:') || // unique local
        cleanIP.startsWith('fd00:') // unique local
      );
    }
    
    return false;
  }

  // Separar IPs válidos por tipo, excluindo privados
  const validIPv6: string[] = [];
  const validIPv4: string[] = [];
  
  for (const ip of candidateIPs) {
    if (isValidIPv6(ip) && !isPrivateIP(ip)) {
      validIPv6.push(ip);
    } else if (isValidIPv4(ip) && !isPrivateIP(ip)) {
      validIPv4.push(ip);
    }
  }

  // 🎯 PRIORIDADE IPv6: Conforme recomendação da Meta
  if (validIPv6.length > 0) {
    const selectedIP = validIPv6[0];
    console.log('🌐 IPv6 detectado (prioridade):', selectedIP);
    return { ip: selectedIP, type: 'IPv6' };
  }
  
  // Fallback para IPv4
  if (validIPv4.length > 0) {
    const selectedIP = validIPv4[0];
    console.log('🌐 IPv4 detectado (fallback):', selectedIP);
    return { ip: selectedIP, type: 'IPv4' };
  }
  
  // Último recurso: usar qualquer IP disponível
  const fallbackIP = candidateIPs[0] || 'unknown';
  console.warn('⚠️ IP não identificado, usando fallback:', fallbackIP);
  return { ip: fallbackIP, type: 'unknown' };
}

// ✅ NOVA FUNÇÃO: Processamento robusto do FBC
function processFbc(fbc: string): string | null {
  // ... existing code ...
  if (!fbc || typeof fbc !== 'string') {
    console.warn('⚠️ FBC inválido:', fbc);
    return null;
  }

  const trimmedFbc = fbc.trim();
  
  // Formato padrão: fb.1.timestamp.fbclid
  const fbcPattern = /^fb\.1\.[0-9]+\.[A-Za-z0-9_-]+$/;
  if (fbcPattern.test(trimmedFbc)) {
    console.log('✅ FBC válido (formato padrão):', trimmedFbc);
    return trimmedFbc;
  }
  
  // Formato fbclid puro (sem prefixo)
  const fbclidPattern = /^[A-Za-z0-9_-]+$/;
  if (fbclidPattern.test(trimmedFbc)) {
    const timestamp = Math.floor(Date.now() / 1000);
    const formattedFbc = `fb.1.${timestamp}.${trimmedFbc}`;
    console.log('✅ FBC formatado de fbclid puro:', formattedFbc);
    return formattedFbc;
  }
  
  // Formato com prefixo fbclid=
  if (trimmedFbc.startsWith('fbclid=')) {
    const fbclid = trimmedFbc.substring(7);
    if (fbclidPattern.test(fbclid)) {
      const timestamp = Math.floor(Date.now() / 1000);
      const formattedFbc = `fb.1.${timestamp}.${fbclid}`;
      console.log('✅ FBC formatado de fbclid com prefixo:', formattedFbc);
      return formattedFbc;
    }
  }
  
  console.warn('⚠️ FBC formato inválido:', trimmedFbc);
  return null;
}

const RATE_LIMIT = 30;
const rateLimitMap = new Map<string, number[]>();

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

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const startTime = Date.now();
  
  // 🌐 DETECÇÃO INTELIGENTE DE IP: Prioriza IPv6
  const { ip, type: ipType } = getClientIP(req);
  
  const userAgent = req.headers["user-agent"] || "";
  const origin = req.headers.origin;

  const ALLOWED_ORIGINS = [
    "https://www.digitalpaisagismo.com",
    "https://digitalpaisagismo.com",
    "https://cap.digitalpaisagismo.com",
    "https://atendimento.digitalpaisagismo.com",
    "https://projeto.digitalpaisagismo.com",
    "https://www.projeto.digitalpaisagismo.com",
    "http://localhost:3000",
    "http://localhost:8080",
    "http://localhost:8081"
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

    // 🛡️ FILTRO DE DEDUPLICAÇÃO: Remover eventos duplicados
    const originalCount = req.body.data.length;
    const filteredData = req.body.data.filter((event: any) => {
      const eventId = event.event_id || `evt_${Date.now()}_${Math.random().toString(36).substr(2, 10)}`;
      return !isDuplicateEvent(eventId);
    });
    
    const duplicatesBlocked = originalCount - filteredData.length;
    
    if (duplicatesBlocked > 0) {
      console.log(`🛡️ Deduplicação: ${duplicatesBlocked} eventos duplicados bloqueados de ${originalCount}`);
    }
    
    if (filteredData.length === 0) {
      return res.status(200).json({ 
        message: 'Todos os eventos foram filtrados como duplicatas',
        duplicates_blocked: duplicatesBlocked,
        original_count: originalCount,
        cache_size: eventCache.size
      });
    }

    const enrichedData = filteredData.map((event: any) => {
      // ... existing code ...
      // Garantir session_id único se não vier do frontend
      let sessionId = event.session_id;
      if (!sessionId) {
        if (req.cookies && req.cookies.session_id) {
          sessionId = req.cookies.session_id;
        } else {
          sessionId = `sess_${Date.now()}_${Math.random().toString(36).substr(2, 10)}`;
        }
      }
      
      const externalId = sessionId ? hashSHA256(sessionId) : null;
      const eventId = event.event_id || `evt_${Date.now()}_${Math.random().toString(36).substr(2, 10)}`;
      const eventName = event.event_name || "Lead";
      const eventSourceUrl = event.event_source_url || origin || req.headers.referer || "https://www.digitalpaisagismo.com";
      const eventTime = event.event_time ? Math.floor(Number(event.event_time)) : Math.floor(Date.now() / 1000);
      const actionSource = event.action_source || "website";

      // Padronizar custom_data (removido processamento de VideoProgress)
      const customData = { ...event.custom_data };
      if (["PageView", "ViewContent"].includes(eventName)) {
        delete customData.value;
        delete customData.currency;
      }
      
      // Para Lead, garantir value/currency dinâmicos
      if (eventName === "Lead") {
        customData.value = typeof customData.value !== 'undefined' ? customData.value : 5000;
        customData.currency = customData.currency || "BRL";
      }

      // ✅ SEM PII: user_data apenas com dados técnicos e geo-enrichment
      const userData: any = {
        ...(externalId && { external_id: [externalId] }),
        client_ip_address: ip, // 🌐 IP otimizado (IPv6 prioritário)
        client_user_agent: userAgent,
      };
      
      // Processamento robusto do FBP
      if (typeof event.user_data?.fbp === "string" && event.user_data.fbp.startsWith("fb.")) {
        const fbpPattern = /^fb\.[0-9]+\.[0-9]+\.[A-Za-z0-9_-]+$/;
        if (fbpPattern.test(event.user_data.fbp)) {
          userData.fbp = event.user_data.fbp;
          console.log('✅ FBP válido preservado:', event.user_data.fbp);
        } else {
          console.warn('⚠️ FBP formato inválido ignorado:', event.user_data.fbp);
        }
      }
      
      // ✅ CORREÇÃO: Processamento robusto do FBC usando a nova função
      if (event.user_data?.fbc) {
        const processedFbc = processFbc(event.user_data.fbc);
        if (processedFbc) {
          userData.fbc = processedFbc;
          console.log('✅ FBC processado e preservado:', processedFbc);
        }
      }
      
      // 🌍 GEO-ENRICHMENT: Preservar dados de geolocalização do frontend
      if (typeof event.user_data?.country === "string" && event.user_data.country.trim()) {
        userData.country = event.user_data.country.toLowerCase().trim();
        console.log('🌍 Country adicionado:', userData.country);
      }
      if (typeof event.user_data?.state === "string" && event.user_data.state.trim()) {
        userData.state = event.user_data.state.toLowerCase().trim();
        console.log('🌍 State adicionado:', userData.state);
      }
      if (typeof event.user_data?.city === "string" && event.user_data.city.trim()) {
        userData.city = event.user_data.city.toLowerCase().trim();
        console.log('🌍 City adicionado:', userData.city);
      }

      return {
        event_name: eventName,
        event_id: eventId,
        event_time: eventTime,
        event_source_url: eventSourceUrl,
        action_source: actionSource,
        custom_data: customData,
        user_data: userData
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

    console.log("🔄 Enviando evento para Meta CAPI (IPv6 + Deduplicação):", {
      events: enrichedData.length,
      original_events: originalCount,
      duplicates_blocked: duplicatesBlocked,
      event_names: enrichedData.map(e => e.event_name),
      ip_type: ipType,
      client_ip: ip,
      has_pii: false,
      has_geo_data: enrichedData.some(e => e.user_data.country || e.user_data.state || e.user_data.city),
      geo_locations: enrichedData
        .filter(e => e.user_data.country)
        .map(e => `${e.user_data.country}/${e.user_data.state}/${e.user_data.city}`)
        .slice(0, 3),
      fbc_processed: enrichedData.filter(e => e.user_data.fbc).length,
      cache_size: eventCache.size
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
        events: enrichedData.length,
        ip_type: ipType,
        duplicates_blocked
      });

      return res.status(response.status).json({
        error: "Erro da Meta",
        details: data,
        processing_time_ms: responseTime
      });
    }

    console.log("✅ Evento enviado com sucesso para Meta CAPI:", {
      events_processed: enrichedData.length,
      duplicates_blocked: duplicatesBlocked,
      processing_time_ms: responseTime,
      compression_used: shouldCompress,
      ip_type: ipType,
      cache_size: eventCache.size
    });

    res.status(200).json({
      ...data,
      ip_info: { type: ipType, address: ip },
      deduplication_info: {
        original_events: originalCount,
        processed_events: enrichedData.length,
        duplicates_blocked: duplicatesBlocked,
        cache_size: eventCache.size
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
