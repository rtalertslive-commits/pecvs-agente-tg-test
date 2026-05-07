# Cloud Functions — Actividad PECVS Telegram Mini App

Backend para verificar la autenticación Telegram del Mini App del agente.

## Función deployada

### `verifyTelegramAuth`

**Tipo:** HTTPS Callable (Gen 2)
**Region:** `us-central1`
**Secret requerido:** `TELEGRAM_BOT_TOKEN`

**Input:**
```js
{
  initData: "<string firmado por Telegram>"
}
```

**Output (success):**
```js
{
  token: "<Firebase custom token>",
  user: {
    id: 123456789,
    username: "franco_cappello",
    first_name: "Franco",
    last_name: "Cappello",
    language_code: "es",
    is_premium: false
  }
}
```

**Output (error):**
- `invalid-argument` — falta initData
- `unauthenticated` — initData inválido (firma mala, expirado, etc)
- `failed-precondition` — bot token no configurado en secrets

El `uid` del custom token es siempre `"tg_" + telegram_user_id`.

## Setup local (primera vez)

```bash
# 1. Login a Firebase (interactivo, abre browser)
firebase login

# 2. Verificar proyecto
firebase use pecvs-testnet

# 3. Setear el bot token como secret (te pedirá pegarlo)
firebase functions:secrets:set TELEGRAM_BOT_TOKEN

# 4. Instalar dependencias
cd functions
npm install
cd ..

# 5. Deploy
firebase deploy --only functions
```

## Updates al bot token (rotación)

```bash
firebase functions:secrets:set TELEGRAM_BOT_TOKEN
firebase deploy --only functions   # re-deploy para que tome el secret nuevo
```

## Logs en tiempo real

```bash
firebase functions:log --only verifyTelegramAuth
```

## Notas de seguridad

- El bot token NUNCA se commitea a git ni vive en archivos `.env`
- Usa Google Cloud Secret Manager (vía `defineSecret`)
- Solo procesos autorizados (la function deployada) pueden leerlo en runtime
- `cors: true` permite que el Mini App lo llame desde GitHub Pages
- `auth_date` se valida con TTL de 24h para prevenir replay attacks
