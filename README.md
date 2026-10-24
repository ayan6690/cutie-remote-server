# Cutie Remote Server dashboard prototype

## Deploy
1. Replace repository `main.py` and `requirements.txt` with these files.
2. In Render Environment, set `CUTIE_API_KEY` to a long random secret and `CUTIE_PAIRING_CODE` to a different random secret (at least 8 characters).
3. Deploy latest commit.
4. Open `/` for dashboard, `/docs` for API docs, `/health` for health check.

## Important prototype limits
- Dashboard asks for the API key in the page; it is kept in memory only and is sent over HTTPS as `X-API-Key`.
- This is not production-grade authentication: no login sessions, rate limiting, persistent database, CSRF/session system, or per-device tokens yet.
- Pair endpoint only validates a code; it does not persist pairing.
- Commands are in-memory, reset on restart, and only record `status`, `scan`, `build` requests. They are NOT executed on a device.
- Camera, microphone, SMS, WhatsApp, and other sensitive device features are disabled and not implemented.
