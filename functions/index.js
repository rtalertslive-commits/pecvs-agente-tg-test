// Cloud Functions for Actividad PECVS — Telegram Mini App backend
//
// verifyTelegramAuth:
//   - Recibe initData firmado por Telegram desde el Mini App
//   - Valida HMAC-SHA256 con BOT_TOKEN (fórmula oficial Telegram)
//   - Si valido: emite Firebase custom token con uid = "tg_" + telegram_user_id
//   - Si invalido: rechaza (intento de spoof de identidad)
//
// El bot token se guarda como secreto via:
//   firebase functions:secrets:set TELEGRAM_BOT_TOKEN
//
// Doc oficial Telegram: https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app

const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { setGlobalOptions } = require('firebase-functions/v2');
const { defineSecret } = require('firebase-functions/params');
const { initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const crypto = require('node:crypto');

initializeApp();

setGlobalOptions({
    region: 'us-central1',
    maxInstances: 10,
});

const TELEGRAM_BOT_TOKEN = defineSecret('TELEGRAM_BOT_TOKEN');

// ─── VALIDACION DE initData (algoritmo oficial Telegram) ───────────────────
// 1. Parsear initData (formato URL-encoded query string)
// 2. Extraer 'hash'
// 3. Ordenar resto de campos alfabeticamente: key=value\nkey=value\n...
// 4. secret = HMAC-SHA256("WebAppData", BOT_TOKEN)
// 5. computed_hash = HMAC-SHA256(secret, data_check_string).hex()
// 6. computed_hash debe == hash recibido
// 7. auth_date debe ser reciente (1 dia max para evitar replay)
function verifyInitData(initData, botToken) {
    if (typeof initData !== 'string' || initData.length === 0) {
        return { ok: false, error: 'initData empty' };
    }

    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    if (!hash) return { ok: false, error: 'missing hash' };
    params.delete('hash');

    const dataCheckString = [...params.entries()]
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([k, v]) => `${k}=${v}`)
        .join('\n');

    const secretKey = crypto.createHmac('sha256', 'WebAppData')
        .update(botToken)
        .digest();
    const computedHash = crypto.createHmac('sha256', secretKey)
        .update(dataCheckString)
        .digest('hex');

    if (computedHash !== hash) {
        return { ok: false, error: 'signature mismatch' };
    }

    // Anti-replay: auth_date debe ser reciente
    const authDate = parseInt(params.get('auth_date'), 10);
    const now = Math.floor(Date.now() / 1000);
    if (!authDate || (now - authDate) > 86400) {
        return { ok: false, error: 'expired (auth_date > 24h)' };
    }

    // Extraer user
    const userJson = params.get('user');
    if (!userJson) return { ok: false, error: 'missing user field' };

    let user;
    try {
        user = JSON.parse(userJson);
    } catch (e) {
        return { ok: false, error: 'invalid user JSON' };
    }

    if (!user.id || typeof user.id !== 'number') {
        return { ok: false, error: 'invalid user.id' };
    }

    return { ok: true, user };
}

// ─── CALLABLE FUNCTION ─────────────────────────────────────────────────────
exports.verifyTelegramAuth = onCall(
    {
        secrets: [TELEGRAM_BOT_TOKEN],
        cors: true,
    },
    async (request) => {
        const initData = request.data?.initData;
        if (!initData) {
            throw new HttpsError('invalid-argument', 'Missing initData');
        }

        const botToken = TELEGRAM_BOT_TOKEN.value();
        if (!botToken) {
            throw new HttpsError('failed-precondition', 'Bot token not configured');
        }

        const result = verifyInitData(initData, botToken);
        if (!result.ok) {
            console.warn('verifyTelegramAuth rejected:', result.error);
            throw new HttpsError('unauthenticated', `Invalid initData: ${result.error}`);
        }

        const uid = `tg_${result.user.id}`;

        // Custom claims que viajan dentro del JWT — accesibles via auth.token.X en
        // Firestore Rules sin necesidad de leer el doc del usuario.
        const claims = {
            telegram_id: result.user.id,
            telegram_username: result.user.username || null,
            auth_provider: 'telegram',
        };

        const customToken = await getAuth().createCustomToken(uid, claims);

        return {
            token: customToken,
            user: {
                id: result.user.id,
                username: result.user.username || null,
                first_name: result.user.first_name || null,
                last_name: result.user.last_name || null,
                language_code: result.user.language_code || null,
                is_premium: result.user.is_premium || false,
            },
        };
    }
);
