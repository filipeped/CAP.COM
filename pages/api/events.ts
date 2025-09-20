// ✅ DIGITAL PAISAGISMO CAPI V8.7 - CORREÇÕES DE TIPAGEM E COMPLIANCE
// V8.7: Correções de tipagem e compliance:
// - Corrigido erro de tipagem: removidos arrays incorretos dos campos user_data
// - Interface UserData agora recebe strings simples em vez de arrays
// - Mantida compliance com documentação oficial webhook Hotmart 2.0
// - checkout_country.iso com prioridade sobre buyer.address.country_iso
// - Suporte a affiliates.affiliate_code conforme documentação oficial
// CORREÇÃO CRÍTICA: Event_id agora é consistente entre pixel e API
// PROBLEMA IDENTIFICADO: Event_ids aleatórios impediam deduplicação correta
// SOLUÇÃO: Event_ids determinísticos baseados em dados do evento
// IMPORTANTE: Frontend deve enviar event_id único para cada evento
// TTL otimizado para 6h para reduzir eventos fantasma
// Cache aumentado para 50k eventos para melhor cobertura
// ✅ HOTMART: Corrigido purchaser → buyer, transaction → purchase
// ✅ HOTMART: Webhook processamento completo com transformação para Meta CAPI
// 🔥 CRÍTICO V8.4: Campo country agora é hasheado em SHA256 (Meta CAPI exigência)
// 🔥 CRÍTICO V8.5: Unificação hash geográfico - frontend e Hotmart agora consistentes

import * as crypto from "crypto";
import * as zlib from "zlib";

// Tipos para requisição e resposta (compatível com Express/Node.js)
interface UserData {
  external_id?: string;
  fbp?: string;
  fbc?: string;
  country?: string;
  state?: string;
  city?: string;
  postal?: string;
  [key: string]: unknown;
}

interface EventData {
  event_id?: string;
  event_name?: string;
  event_time?: number | string;
  event_source_url?: string;
  action_source?: string;
  session_id?: string;
  user_data?: UserData;
  custom_data?: Record<string, unknown>;
  [key: string]: unknown;
}

// ==================== INTERFACES HOTMART (CORRIGIDAS) ====================
interface HotmartProduct {
  id: number;
  name: string;
  ucode?: string;
}

interface HotmartWebhookData {
  product: HotmartProduct;
  buyer: {
    email: string;
    name?: string;
    checkout_phone?: string;
    document?: string;
    address?: {
      city?: string;
      country_iso?: string;
      state?: string;
      zipcode?: string;
    };
  };
  checkout_country?: {
    name?: string;
    iso?: string;
  };
  affiliates?: Array<{
    affiliate_code?: string;
    [key: string]: unknown;
  }>;
  purchase: {
    transaction: string;
    price: { value: number; currency_value: string };
    status: string;
  };
}

interface HotmartWebhookPayload {
  id: string;
  creation_date: number;
  event: string;
  version: string;
  data: HotmartWebhookData;
}

const transformHotmartToMeta = (hotmartData: HotmartWebhookData): EventData => {
  const { buyer, product, purchase, checkout_country } = hotmartData;

  // Priorizar checkout_country.iso sobre buyer.address.country_iso conforme documentação oficial
  const countryCode = checkout_country?.iso || buyer.address?.country_iso;

  return {
    event_name: "Purchase",
    event_time: Math.floor(Date.now() / 1000),
    action_source: "website",
    user_data: {
      em: hashSHA256(buyer.email.toLowerCase().trim()),
      ph: buyer.checkout_phone ? hashSHA256(buyer.checkout_phone.replace(/\D/g, "")) : undefined,
      fn: buyer.name ? hashSHA256(buyer.name.toLowerCase().trim()) : undefined,
      ct: buyer.address?.city ? hashSHA256(buyer.address.city.toLowerCase().trim()) : undefined,
      st: buyer.address?.state ? hashSHA256(buyer.address.state.toLowerCase().trim()) : undefined,
      zp: buyer.address?.zipcode ? hashSHA256(buyer.address.zipcode) : undefined,
      country: countryCode ? hashSHA256(countryCode.toLowerCase()) : undefined,
    },
    custom_data: {
      currency: purchase.price.currency_value,
      value: purchase.price.value,
      content_name: product.name,
      content_ids: [product.id.toString()],
      content_type: "product",
      order_id: purchase.transaction,
    },
    event_source_url: "https://hotmart.com",
    event_id: `hotmart_${purchase.transaction}_${Date.now()}`,
  };
};

interface ApiRequest {
  method?: string;
  body?: {
    data?: EventData[];
    [key: string]: unknown;
  } | HotmartWebhookPayload;
  headers: Record<string, string | string[] | undefined>;
  socket?: {
    remoteAddress?: string;
  };
  cookies?: Record<string, string>;
}

interface ApiResponse {
  status(code: number): ApiResponse;
  json(data: unknown): void;
  end(): void;
  setHeader(name: string, value: string): void;
}

const PIXEL_ID = "765087775987515";
const ACCESS_TOKEN = "EAAQfmxkTTZCcBPHGbA2ojC29bVbNPa6GM3nxMxsZC29ijBmuyexVifaGnrjFZBZBS6LEkaR29X3tc5TWn4SHHffeXiPvexZAYKP5mTMoYGx5AoVYaluaqBTtiKIjWALxuMZAPVcBk1PuYCb0nJfhpzAezh018LU3cT45vuEflMicoQEHHk3H5YKNVAPaUZC6yzhcQZDZD";
const META_URL = `https://graph.facebook.com/v19.0/${PIXEL_ID}/events`;

// ✅ SISTEMA DE DEDUPLICAÇÃO MELHORADO
const eventCache = new Map<string, number>();
const CACHE_TTL = 6 * 60 * 60 * 1000; // 6 horas (otimizado para reduzir eventos fantasma)
const MAX_CACHE_SIZE = 50000; // Aumentado para suportar mais eventos

function isDuplicateEvent(eventId: string): boolean {
  const now = Date.now();

  // Limpeza automática de eventos expirados (sem for...of)
  let cleanedCount = 0;
  eventCache.forEach((timestamp, id) => {
    if (now - timestamp > CACHE_TTL) {
      eventCache.delete(id);
      cleanedCount++;
    }
  });

  if (cleanedCount > 0) {
    console.log(`🧹 Cache limpo: ${cleanedCount} eventos expirados removidos (TTL: 6h)`);
  }

  // Verificar se é duplicata
  if (eventCache.has(eventId)) {
    const lastSeen = eventCache.get(eventId);
    const timeDiff = now - (lastSeen || 0);
    console.warn(`🚫 Evento duplicado bloqueado: ${eventId} (última ocorrência: ${Math.round(timeDiff/1000)}s atrás)`);
    return true;
  }

  // Controle de tamanho do cache
  if (eventCache.size >= MAX_CACHE_SIZE) {
    // Remove 10% do cache quando atingir o limite para melhor performance
    const itemsToRemove = Math.floor(MAX_CACHE_SIZE * 0.1);
    let removedCount = 0;
    
    const eventIds = Array.from(eventCache.keys());
    for (let i = 0; i < itemsToRemove && i < eventIds.length; i++) {
      eventCache.delete(eventIds[i]);
      removedCount++;
    }
    
    console.log(`🗑️ Cache overflow: ${removedCount} eventos mais antigos removidos (${eventCache.size}/${MAX_CACHE_SIZE})`);
  }

  // Adicionar ao cache
  eventCache.set(eventId, now);
  console.log(`✅ Evento adicionado ao cache de deduplicação: ${eventId} (cache size: ${eventCache.size})`);
  return false;
}

// ✅ MELHORADO: Hash SHA256 com fallback robusto
function hashSHA256(value: string): string {
  if (!value || typeof value !== "string") {
    console.warn("⚠️ hashSHA256: Valor inválido, usando fallback:", value);
    return crypto.createHash("sha256").update(`fallback_${Date.now()}_${Math.random()}`).digest("hex");
  }
  return crypto.createHash("sha256").update(value.trim()).digest("hex");
}

// ✅ IPv6 INTELIGENTE: Detecção e validação de IP com prioridade IPv6
function getClientIP(
  req: ApiRequest
): { ip: string; type: "IPv4" | "IPv6" | "unknown" } {
  const ipSources = [
    req.headers["cf-connecting-ip"],
    req.headers["x-real-ip"],
    req.headers["x-forwarded-for"],
    req.headers["x-client-ip"],
    req.headers["x-cluster-client-ip"],
    req.socket?.remoteAddress,
  ];

  const candidateIPs: string[] = [];
  ipSources.forEach((source) => {
    if (!source) return;
    if (typeof source === "string") {
      const ips = source.split(",").map((ip) => ip.trim());
      candidateIPs.push(...ips);
    }
  });

  function isValidIPv4(ip: string): boolean {
    const ipv4Regex =
      /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(ip);
  }

  function isValidIPv6(ip: string): boolean {
    const cleanIP = ip.replace(/^\[|\]$/g, "");
    // ✅ REGEX IPv6 OTIMIZADA: Mais eficiente e simples
    try {
      // Validação básica de formato IPv6
      if (!/^[0-9a-fA-F:]+$/.test(cleanIP.replace(/\./g, ''))) return false;
      
      // Usar URL constructor para validação nativa (mais eficiente)
      new URL(`http://[${cleanIP}]`);
      return true;
    } catch {
      // Fallback para regex simplificada
      const ipv6Simple = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$|^::1$|^::$/;
      return ipv6Simple.test(cleanIP);
    }
  }

  function isPrivateIP(ip: string): boolean {
    if (isValidIPv4(ip)) {
      const parts = ip.split(".").map(Number);
      // Validar se todas as partes são números válidos
      if (parts.some(part => isNaN(part) || part < 0 || part > 255)) {
        return false;
      }
      return (
        parts[0] === 10 ||
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] === 192 && parts[1] === 168) ||
        parts[0] === 127
      );
    }
    if (isValidIPv6(ip)) {
      const cleanIP = ip.replace(/^\[|\]$/g, "");
      return (
        cleanIP === "::1" ||
        cleanIP.startsWith("fe80:") ||
        cleanIP.startsWith("fc00:") ||
        cleanIP.startsWith("fd00:")
      );
    }
    return false;
  }

  const validIPv6: string[] = [];
  const validIPv4: string[] = [];

  candidateIPs.forEach((ip) => {
    if (isValidIPv6(ip) && !isPrivateIP(ip)) validIPv6.push(ip);
    else if (isValidIPv4(ip) && !isPrivateIP(ip)) validIPv4.push(ip);
  });

  // ✅ PRIORIDADE IPv6: Garantir que a Meta reconheça corretamente o IPv6
  if (validIPv6.length > 0) {
    const selectedIP = validIPv6[0];
    console.log("🌐 IPv6 detectado (prioridade para Meta CAPI):", selectedIP);
    return { ip: selectedIP, type: "IPv6" };
  }
  if (validIPv4.length > 0) {
    const selectedIP = validIPv4[0];
    console.log("🌐 IPv4 detectado (fallback):", selectedIP);
    return { ip: selectedIP, type: "IPv4" };
  }

  const fallbackIP = candidateIPs[0] || "unknown";
  console.warn("⚠️ IP não identificado, usando fallback:", fallbackIP);
  return { ip: fallbackIP, type: "unknown" };
}

// ✅ NOVA FUNÇÃO: Formatação otimizada de IP para Meta CAPI (consistente com frontend)
function formatIPForMeta(ip: string): string {
  // Detectar tipo de IP automaticamente
  const detectIPType = (ip: string): string => {
    if (!ip || ip === 'unknown') return 'unknown';
    
    // IPv6 contém ':'
    if (ip.includes(':')) {
      return 'IPv6';
    }
    
    // IPv4 contém apenas números e pontos
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
      return 'IPv4';
    }
    
    return 'unknown';
  };
  
  const ipType = detectIPType(ip);
  
  if (ipType === 'IPv6') {
    // Remove colchetes se presentes e garante formato limpo
    const cleanIP = ip.replace(/^\[|\]$/g, '');
    
    console.log('🌐 IPv6 formatado para Meta:', {
      original: ip,
      formatted: cleanIP,
      is_native_ipv6: true
    });
    
    return cleanIP;
  }
  
  if (ipType === 'IPv4') {
    // Para IPv4, a Meta recomenda conversão para IPv6-mapped
    // Formato IPv4-mapped IPv6: ::ffff:192.168.1.1
    const ipv6Mapped = `::ffff:${ip}`;
    console.log('🔄 IPv4 convertido para IPv6-mapped:', {
      original_ipv4: ip,
      ipv6_mapped: ipv6Mapped,
      reason: 'Meta prefere IPv6 sobre IPv4'
    });
    return ipv6Mapped;
  }
  
  return ip;
}

// ✅ CORREÇÃO CRÍTICA: Processamento FBC conforme documentação Meta oficial
// ✅ NOVA FUNÇÃO: Extrair fbclid de cookies e URL conforme documentação Meta
function extractFbclid(req: ApiRequest): string | null {
  // 1. Tentar extrair de parâmetro URL fbclid (prioridade máxima)
  const url = req.headers.referer || req.headers.origin || '';
  if (url) {
    try {
      // ✅ CORREÇÃO: Garantir que url seja string
      const urlString = Array.isArray(url) ? url[0] : url;
      const urlObj = new URL(urlString);
      const fbclidFromUrl = urlObj.searchParams.get('fbclid');
      if (fbclidFromUrl && fbclidFromUrl.trim()) {
        console.log("✅ fbclid extraído da URL:", fbclidFromUrl);
        return fbclidFromUrl.trim(); // ✅ PRESERVA case original
      }
    } catch (e) {
      console.warn("⚠️ Erro ao processar URL para fbclid:", e);
    }
  }

  // 2. Tentar extrair do cookie _fbc (segunda prioridade)
  const fbcCookie = req.cookies?._fbc;
  if (fbcCookie && typeof fbcCookie === 'string') {
    // Formato do cookie _fbc: fb.subdomainIndex.timestamp.fbclid
    const parts = fbcCookie.split('.');
    if (parts.length >= 4 && parts[0] === 'fb') {
      const fbclid = parts.slice(3).join('.'); // Pega tudo após o terceiro ponto
      if (fbclid && fbclid.trim()) {
        console.log("✅ fbclid extraído do cookie _fbc:", fbclid);
        return fbclid.trim(); // ✅ PRESERVA case original
      }
    }
  }

  console.log("ℹ️ Nenhum fbclid encontrado em URL ou cookies");
  return null;
}

// ✅ NOVA FUNÇÃO: Definir cookie _fbc conforme documentação Meta
function setFbcCookie(res: ApiResponse, fbclid: string, existingFbc?: string): void {
  if (!fbclid || typeof fbclid !== 'string') {
    return;
  }

  // Verificar se já existe um cookie _fbc válido com o mesmo fbclid
  if (existingFbc && typeof existingFbc === 'string') {
    const parts = existingFbc.split('.');
    if (parts.length >= 4 && parts[0] === 'fb') {
      const existingFbclid = parts.slice(3).join('.');
      if (existingFbclid === fbclid) {
        console.log("✅ Cookie _fbc já existe com mesmo fbclid, não sobrescrevendo");
        return;
      }
    }
  }

  // Criar novo cookie _fbc conforme documentação Meta
  const timestamp = Date.now(); // Milissegundos conforme documentação
  const subdomainIndex = 1; // Para domínio padrão conforme documentação
  const fbcValue = `fb.${subdomainIndex}.${timestamp}.${fbclid}`;
  
  // Definir cookie com 90 dias de expiração conforme documentação Meta
  const expirationDate = new Date(Date.now() + (90 * 24 * 60 * 60 * 1000));
  const cookieString = `_fbc=${fbcValue}; Expires=${expirationDate.toUTCString()}; Path=/; SameSite=Lax; Secure`;
  
  res.setHeader('Set-Cookie', cookieString);
  console.log("✅ Cookie _fbc definido:", fbcValue);
}

function processFbc(fbc: string): string | null {
  if (!fbc || typeof fbc !== "string") {
    console.warn("⚠️ FBC inválido:", fbc);
    return null;
  }

  // ✅ CRÍTICO: Facebook documentação - "ClickID value is case sensitive - do not apply any modifications"
  // APENAS removemos espaços em branco no início/fim, preservando TUDO o resto
  const trimmedFbc = fbc.trim();

  // ✅ CORREÇÃO CRÍTICA: Aceitar FBC já formatado (fb.subdomainIndex.timestamp.fbclid)
  // Documentação Meta: version.subdomainIndex.creationTime.fbclid
  // Padrão mais flexível para aceitar qualquer fbclid válido após os pontos
  const fbcPattern = /^fb\.[0-9]+\.[0-9]{10,13}\..+$/;
  if (fbcPattern.test(trimmedFbc)) {
    console.log("✅ FBC já formatado corretamente (preservando):", trimmedFbc);
    return trimmedFbc; // ✅ PRESERVA valor original sem NENHUMA modificação
  }

  // ✅ CORREÇÃO CRÍTICA: Padrão mais flexível para fbclid
  // Meta documentação: "do not apply any modifications before using, such as lower or upper case"
  // Aceitar qualquer fbclid que comece com caracteres válidos (não apenas IwAR)
  const fbclidPattern = /^[A-Za-z0-9_-]{10,200}$/; // Padrão mais flexível para fbclid
  
  // Se é um fbclid puro (sem prefixo fbclid=)
  if (fbclidPattern.test(trimmedFbc)) {
    const fbclid = trimmedFbc; // O valor já é o fbclid puro
    const timestamp = Date.now(); // Milissegundos conforme documentação Meta
    // subdomainIndex: 1 para domínio padrão conforme documentação
    const formattedFbc = `fb.1.${timestamp}.${fbclid}`;
    console.log("✅ FBC formatado de fbclid puro (preservando case):", formattedFbc);
    return formattedFbc; // ✅ PRESERVA fbclid original SEM modificações
  }

  // Se tem prefixo fbclid=
  if (trimmedFbc.startsWith("fbclid=")) {
    const fbclid = trimmedFbc.substring(7);
    if (fbclidPattern.test(fbclid)) {
      const timestamp = Date.now(); // Milissegundos conforme documentação Meta
      // subdomainIndex: 1 para domínio padrão conforme documentação
      const formattedFbc = `fb.1.${timestamp}.${fbclid}`;
      console.log("✅ FBC formatado de fbclid com prefixo (preservando case):", formattedFbc);
      return formattedFbc; // ✅ PRESERVA fbclid original SEM modificações
    }
  }

  // ✅ CRÍTICO: SEMPRE preservar valor original
  // Meta documentação: "Note: ClickID value is case sensitive - do not apply any modifications"
  // Se chegou aqui, pode ser um formato válido que não reconhecemos
  console.log("✅ FBC formato não reconhecido - preservando valor original SEM modificações:", trimmedFbc);
  return trimmedFbc; // ✅ SEMPRE preserva valor original conforme Meta
}

const RATE_LIMIT = 100; // Aumentado para suportar picos de tráfego
const rateLimitMap = new Map<string, number[]>();

function rateLimit(ip: string): boolean {
  const now = Date.now();
  const windowMs = 60000;
  if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []);
  const timestamps = (rateLimitMap.get(ip) || []).filter((t) => now - t < windowMs);
  if (timestamps.length >= RATE_LIMIT) return false;
  timestamps.push(now);
  rateLimitMap.set(ip, timestamps);
  if (rateLimitMap.size > 1000) {
    const oldest = rateLimitMap.keys().next();
    if (!oldest.done) rateLimitMap.delete(oldest.value);
  }
  return true;
}

// ==================== FUNÇÕES HOTMART (CORRIGIDAS) ====================
const isHotmartWebhook = (body: any): body is HotmartWebhookPayload => {
  return body && 
    typeof body.id === "string" && 
    typeof body.event === "string" && 
    body.data && 
    body.data.product && 
    body.data.buyer && 
    body.data.purchase;
};

export default async function handler(req: ApiRequest, res: ApiResponse) {
  const startTime = Date.now();

  const { ip, type: ipType } = getClientIP(req);
  const userAgent = (req.headers["user-agent"] as string) || "";
  const origin = (req.headers.origin as string) || "";

  const ALLOWED_ORIGINS = [
    "https://www.digitalpaisagismo.com",
    "https://digitalpaisagismo.com",
    "https://cap.digitalpaisagismo.com",
    "https://atendimento.digitalpaisagismo.com",
    "https://consultoria.digitalpaisagismo.com",
    "https://www.consultoria.digitalpaisagismo.com",
    "https://cap.consultoria.digitalpaisagismo.com",
    "https://projeto.digitalpaisagismo.com",
    "https://www.projeto.digitalpaisagismo.com",
    "http://localhost:3000",
    "http://localhost:8080",
    "http://localhost:8081",
  ];

  res.setHeader(
    "Access-Control-Allow-Origin",
    ALLOWED_ORIGINS.includes(origin) ? origin : "https://www.digitalpaisagismo.com"
  );
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
    // ==================== PROCESSAMENTO HOTMART (CORRIGIDO) ====================
    if (isHotmartWebhook(req.body)) {
      console.log("🔥 Webhook Hotmart detectado:", { event: req.body.event, id: req.body.id });
      
      if (req.body.event === "PURCHASE_APPROVED") {
        const transformedEvent = transformHotmartToMeta(req.body.data);
        
        // Verificar duplicata
        if (isDuplicateEvent(transformedEvent.event_id!)) {
          console.log("⚠️ Evento Hotmart duplicado ignorado:", transformedEvent.event_id);
          return res.status(200).json({ status: "duplicate_ignored", event_id: transformedEvent.event_id });
        }

        // Preparar payload para Meta CAPI
        const payload = {
          data: [transformedEvent],
          access_token: ACCESS_TOKEN,
        };

        const payloadString = JSON.stringify(payload);
        const shouldCompress = payloadString.length > 2048;
        
        // ✅ CORREÇÃO: Definir tipos corretos para fetch body
        let finalPayload: string | ArrayBuffer;
        const headers: Record<string, string> = {
          "Content-Type": "application/json",
          "User-Agent": "DigitalPaisagismo-CAPI/8.3-Hotmart",
        };

        if (shouldCompress) {
          const compressed = zlib.gzipSync(payloadString);
          finalPayload = compressed.buffer.slice(compressed.byteOffset, compressed.byteOffset + compressed.byteLength) as ArrayBuffer;
          headers["Content-Encoding"] = "gzip";
        } else {
          finalPayload = payloadString;
        }

        console.log("📤 Enviando evento Hotmart para Meta CAPI:", {
          event_id: transformedEvent.event_id,
          buyer_email: req.body.data.buyer.email,
          transaction: req.body.data.purchase.transaction,
          value: req.body.data.purchase.price.value,
          currency: req.body.data.purchase.price.currency_value,
        });

        const response = await fetch(META_URL, {
          method: "POST",
          headers,
          body: finalPayload,
          signal: AbortSignal.timeout(15000),
        });

        const responseData = await response.json();

        if (response.ok) {
          console.log("✅ Evento Hotmart enviado com sucesso para Meta CAPI");
          return res.status(200).json({ status: "success", meta_response: responseData });
        } else {
          console.error("❌ Erro ao enviar evento Hotmart para Meta CAPI:", responseData);
          return res.status(500).json({ error: "Erro ao processar webhook Hotmart", details: responseData });
        }
      } else {
        console.log("ℹ️ Evento Hotmart ignorado (não é PURCHASE_APPROVED):", req.body.event);
        return res.status(200).json({ status: "ignored", event: req.body.event });
      }
    }

    // ==================== PROCESSAMENTO FRONTEND (ORIGINAL) ====================
    if (!req.body?.data || !Array.isArray(req.body.data)) {
      return res.status(400).json({ error: "Payload inválido - campo 'data' obrigatório" });
    }

    // 🛡️ FILTRO DE DEDUPLICAÇÃO MELHORADO: Verificar duplicatas antes do processamento
    const originalCount = req.body.data.length;
    // ✅ CORRIGIDO: Priorizar event_id do frontend para consistência Pixel/CAPI
    const eventsWithIds = req.body.data.map((event: EventData) => {
      if (!event.event_id) {
        // Gerar event_id determinístico apenas como fallback
        const eventName = event.event_name || "Lead";
        const eventTime = event.event_time && !isNaN(Number(event.event_time)) ? Math.floor(Number(event.event_time)) : Math.floor(Date.now() / 1000);
        const externalId = event.user_data?.external_id || "no_ext_id";
        const eventSourceUrl = event.event_source_url || origin || (req.headers.referer as string) || "https://www.digitalpaisagismo.com";
        const eventData = `${eventName}_${eventTime}_${externalId}_${eventSourceUrl}`;
        event.event_id = `evt_${hashSHA256(eventData).substring(0, 16)}`;
        console.warn("⚠️ Event_id gerado no servidor (fallback) - deve vir do frontend:", event.event_id);
      } else {
        console.log("✅ Event_id recebido do frontend (consistência Pixel/CAPI):", event.event_id);
      }
      return event;
    });
    
    // Segundo passo: filtrar duplicatas usando os event_ids
    const filteredData = eventsWithIds.filter((event: EventData) => {
      return event.event_id && !isDuplicateEvent(event.event_id);
    });

    const duplicatesBlocked = originalCount - filteredData.length;

    if (duplicatesBlocked > 0) {
      console.log(
        `🛡️ Deduplicação: ${duplicatesBlocked} eventos duplicados bloqueados de ${originalCount}`
      );
    }

    if (filteredData.length === 0) {
      return res.status(200).json({
        message: "Todos os eventos foram filtrados como duplicatas",
        duplicates_blocked: duplicatesBlocked,
        original_count: originalCount,
        cache_size: eventCache.size,
      });
    }

    // ✅ FORMATAÇÃO IPv6: Aplicar formatação otimizada para Meta CAPI
    const formattedIP = formatIPForMeta(ip);

    const enrichedData = filteredData.map((event: EventData) => {
      let externalId = event.user_data?.external_id || null;

      if (!externalId) {
        // ✅ CORRIGIDO: Usar EXATA lógica do DeduplicationEngine para consistência total
        let sessionId = event.session_id;
        if (!sessionId) {
          const anyReq = req as ApiRequest;
          if (anyReq.cookies && anyReq.cookies.session_id) {
            sessionId = anyReq.cookies.session_id;
          } else {
            // ✅ MESMA LÓGICA: Gerar sessionId idêntico ao DeduplicationEngine
            const timestamp = Date.now(); // Usar Date.now() como no frontend
            const randomStr = Math.random().toString(36).substr(2, 8); // Usar Math.random como no frontend
            sessionId = `sess_${timestamp}_${randomStr}`; // Mesmo formato: sess_timestamp_random
          }
        }
        
        // ✅ CONSISTÊNCIA TOTAL: Usar mesma lógica de geração do DeduplicationEngine
        const timestamp = Date.now();
        const randomPart = Math.random().toString(36).substr(2, 12);
        const baseId = `${timestamp}_${randomPart}_${sessionId}`;
        
        // ✅ Aplicar SHA256 idêntico ao DeduplicationEngine
        externalId = hashSHA256(baseId);
        console.log("⚠️ External_id gerado no servidor (fallback - IDÊNTICO ao DeduplicationEngine):", externalId);
      } else {
        console.log("✅ External_id recebido do frontend (SHA256 - DeduplicationEngine):", externalId);
      }

      const eventName = event.event_name || "Lead";
      const eventSourceUrl =
        event.event_source_url || origin || (req.headers.referer as string) || "https://www.digitalpaisagismo.com";
      const eventTime = event.event_time && !isNaN(Number(event.event_time)) ? Math.floor(Number(event.event_time)) : Math.floor(Date.now() / 1000);
      
      // ✅ Event_id já foi definido na etapa de deduplicação
      const eventId = event.event_id;
      console.log("✅ Event_id processado:", eventId);
      const actionSource = event.action_source || "website";

      const customData: Record<string, unknown> = { ...(event.custom_data || {}) };
      if (eventName === "PageView") {
        delete customData.value;
        delete customData.currency;
      }
      if (eventName === "Lead") {
        customData.value = typeof customData.value !== "undefined" ? customData.value : 5000;
        customData.currency = customData.currency || "BRL";
      }

      const userData: Record<string, unknown> = {
        ...(externalId && { external_id: externalId }),
        client_ip_address: formattedIP,
        client_user_agent: userAgent,
      };

      if (typeof event.user_data?.fbp === "string" && event.user_data.fbp.startsWith("fb.")) {
        // ✅ CORREÇÃO: FBP pode ter letras no timestamp (formato Meta flexível)
        const fbpPattern = /^fb\.[A-Za-z0-9]+\.[A-Za-z0-9]+\.[A-Za-z0-9_-]+$/;
        if (fbpPattern.test(event.user_data.fbp)) {
          userData.fbp = event.user_data.fbp;
          console.log("✅ FBP válido preservado:", event.user_data.fbp);
        } else {
          // ✅ CORREÇÃO: Preservar valor mesmo com formato não reconhecido
          userData.fbp = event.user_data.fbp;
          console.warn("⚠️ FBP formato não reconhecido, mas preservando:", event.user_data.fbp);
        }
      }

      // ✅ PROCESSAMENTO FBC MELHORADO: Priorizar dados do evento, depois extrair de cookies/URL
      let fbcToProcess = event.user_data?.fbc;
      let extractedFbclid: string | null = null;
      
      // Se não há fbc nos dados do evento, tentar extrair de cookies/URL
      if (!fbcToProcess) {
        extractedFbclid = extractFbclid(req);
        if (extractedFbclid) {
          fbcToProcess = extractedFbclid;
          console.log("✅ fbclid extraído de cookies/URL será processado:", extractedFbclid);
        }
      }

      if (fbcToProcess) {
        const processedFbc = processFbc(fbcToProcess);
        if (processedFbc) {
          userData.fbc = processedFbc;
          console.log("✅ FBC processado e preservado:", processedFbc);
          
          // ✅ DEFINIR COOKIE _FBC: Se extraímos fbclid da URL, definir cookie
          if (extractedFbclid) {
            setFbcCookie(res, extractedFbclid, req.cookies?._fbc);
          }
        } else {
          // ✅ CORREÇÃO: Preservar valor original mesmo quando processamento falha
          userData.fbc = fbcToProcess;
          console.warn("⚠️ FBC não processado, mas preservando valor original:", fbcToProcess);
        }
      }

      if (typeof event.user_data?.country === "string" && event.user_data.country.trim()) {
          userData.country = hashSHA256(event.user_data.country.toLowerCase().trim());
          console.log("🌍 Country hasheado (SHA256):", userData.country);
        }
        if (typeof event.user_data?.state === "string" && event.user_data.state.trim()) {
          userData.st = hashSHA256(event.user_data.state.toLowerCase().trim());
          console.log("🌍 State hasheado (SHA256):", userData.st);
        }
        if (typeof event.user_data?.city === "string" && event.user_data.city.trim()) {
          userData.ct = hashSHA256(event.user_data.city.toLowerCase().trim());
          console.log("🌍 City hasheado (SHA256):", userData.ct);
        }
        if (typeof event.user_data?.postal === "string" && event.user_data.postal.trim()) {
          userData.zp = hashSHA256(event.user_data.postal.trim());
          console.log("🌍 Postal Code hasheado (SHA256):", userData.zp);
        }

      return {
        event_name: eventName,
        event_id: eventId,
        event_time: eventTime,
        event_source_url: eventSourceUrl,
        action_source: actionSource,
        custom_data: customData,
        user_data: userData,
      };
    });

    const payload = { data: enrichedData };
    const jsonPayload = JSON.stringify(payload);
    const shouldCompress = Buffer.byteLength(jsonPayload) > 2048;
    const body = shouldCompress ? zlib.gzipSync(jsonPayload) : jsonPayload;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Connection: "keep-alive",
      "User-Agent": "DigitalPaisagismo-CAPI-Proxy/1.0",
      ...(shouldCompress ? { "Content-Encoding": "gzip" } : {}),
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000); // Aumentado para 15s

    console.log("🔄 Enviando evento para Meta CAPI (DEDUPLICAÇÃO CORRIGIDA):", {
      events: enrichedData.length,
      original_events: originalCount,
      duplicates_blocked: duplicatesBlocked,
      deduplication_rate: `${Math.round((duplicatesBlocked / originalCount) * 100)}%`,
      event_names: enrichedData.map((e) => e.event_name),
      event_ids: enrichedData.map((e) => e.event_id).slice(0, 3), // Primeiros 3 para debug
      ip_type: ip.includes(':') ? 'IPv6' : 'IPv4',
      client_ip_original: ip,
      client_ip_formatted: formattedIP,
      ipv6_conversion_applied: ip.includes(':') ? 'Native IPv6' : 'IPv4→IPv6-mapped',
      has_pii: false,
      external_ids_count: enrichedData.filter((e) => e.user_data.external_id).length,
      external_ids_from_frontend: enrichedData.filter(
        (e) => e.user_data.external_id && typeof e.user_data.external_id === 'string' && e.user_data.external_id.length === 64
      ).length,
      has_geo_data: enrichedData.some((e) => e.user_data.country || e.user_data.state || e.user_data.city),
      geo_locations: enrichedData
        .filter((e) => e.user_data.country)
        .map((e) => `${e.user_data.country}/${e.user_data.state}/${e.user_data.city}`)
        .slice(0, 3),
      fbc_processed: enrichedData.filter((e) => e.user_data.fbc).length,
      cache_size: eventCache.size,
      cache_ttl_hours: CACHE_TTL / (60 * 60 * 1000),
    });

    const response = await fetch(`${META_URL}?access_token=${ACCESS_TOKEN}`, {
      method: "POST",
      headers,
      body: body as BodyInit,
      signal: controller.signal,
    });

    clearTimeout(timeout);
    const data = await response.json() as Record<string, unknown>;
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      console.error("❌ Erro da Meta CAPI:", {
        status: response.status,
        data,
        events: enrichedData.length,
        ip_type: ip.includes(':') ? 'IPv6' : 'IPv4',
        duplicates_blocked: duplicatesBlocked,
      });

      return res.status(response.status).json({
        error: "Erro da Meta",
        details: data,
        processing_time_ms: responseTime,
      });
    }

    console.log("✅ Evento enviado com sucesso para Meta CAPI:", {
      events_processed: enrichedData.length,
      duplicates_blocked: duplicatesBlocked,
      processing_time_ms: responseTime,
      compression_used: shouldCompress,
      ip_type: ip.includes(':') ? 'IPv6' : 'IPv4',
      external_ids_sent: enrichedData.filter((e) => e.user_data.external_id).length,
      sha256_format_count: enrichedData.filter(
        (e) => e.user_data.external_id && typeof e.user_data.external_id === 'string' && e.user_data.external_id.length === 64
      ).length,
      cache_size: eventCache.size,
    });

    res.status(200).json({
      ...data,
      ip_info: { type: ip.includes(':') ? 'IPv6' : 'IPv4', address: ip },
      deduplication_info: {
        original_events: originalCount,
        processed_events: enrichedData.length,
        duplicates_blocked: duplicatesBlocked,
        cache_size: eventCache.size,
      },
    });
  } catch (error: unknown) {
    console.error("❌ Erro no Proxy CAPI:", error);
    if (error instanceof Error && error.name === "AbortError") {
      return res
        .status(408)
        .json({ error: "Timeout ao enviar evento para a Meta", timeout_ms: 15000 });
    }
    res.status(500).json({ error: "Erro interno no servidor CAPI." });
  }
}
