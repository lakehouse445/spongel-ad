// spongel-ad/functions/stream-token.ts
// usage: GET /stream-token?uid=<VIDEO_UID>&ttl=600  (ttl optional; default 600s)

export const onRequestGet: PagesFunction<{
  STREAM_KEY_ID: string
  STREAM_SIGNING_KEY: string
}> = async (ctx) => {
  const url = new URL(ctx.request.url)
  const uid = url.searchParams.get("uid")
  if (!uid) return new Response("missing ?uid", { status: 400 })

  const ttlParam = Number(url.searchParams.get("ttl") || "600")
  const ttl = Number.isFinite(ttlParam) ? Math.max(60, Math.min(ttlParam, 1800)) : 600 // clamp 1–30 min

  const kid = ctx.env.STREAM_KEY_ID
  const pem = ctx.env.STREAM_SIGNING_KEY

  // import PKCS#8 PEM to CryptoKey
  const pkcs8 = decodePemToDer(pem)
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  )

  const now = Math.floor(Date.now() / 1000)
  const payload = {
    sub: uid,              // video uid
    exp: now + ttl,        // expires in ttl seconds
    // add accessRules later if you want geo/state gating
  }
  const header = { alg: "RS256", kid }

  const token = await signJwt(header, payload, privateKey)
  return Response.json({ token, uid, exp: payload.exp })
}

// helpers
function decodePemToDer(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----BEGIN [^-]+-----/g, "")
                 .replace(/-----END [^-]+-----/g, "")
                 .replace(/\s+/g, "")
  const raw = atob(b64)
  const out = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i)
  return out.buffer
}

async function signJwt(header: object, payload: object, key: CryptoKey): Promise<string> {
  const enc = new TextEncoder()
  const b64u = (bytes: Uint8Array) =>
    btoa(String.fromCharCode(...bytes)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
  const part = (obj: object) => b64u(enc.encode(JSON.stringify(obj)))
  const unsigned = `${part(header)}.${part(payload)}`
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(unsigned))
  return `${unsigned}.${b64u(new Uint8Array(sig))}`
}
