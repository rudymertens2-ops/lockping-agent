# LockPing-protocol (schets, v0)

Drie rollen: **agent** (pc), **client** (companion-device), **relay**
(doorgeefluik). Het relay routeert berichten tussen gepairde partijen en kan
de inhoud niet lezen: payloads zijn end-to-end versleuteld tussen agent en
client.

Transport: WebSocket over TLS (WSS) naar het relay. De agent houdt een
permanente uitgaande verbinding open; de client verbindt wanneer de app
openstaat.

## 1. Registratie (agent ↔ relay)

Bij eerste start genereert de agent een sleutelpaar (X25519) en een
`agent_id` (UUID). Hij registreert zich bij het relay en herverbindt daarna
altijd onder dat id. Het relay kent van een agent alleen: id, publieke
sleutel, online/offline.

> **Status ID-bewijs**: de challenge waarmee een verbinding bewijst dat ze
> haar id bezit, is verschoven naar het deploy-increment (vergt persistentie
> aan relay-zijde). Mitigatie tot dan: door E2E + allowlist levert
> id-spoofing hooguit verstoring op (presence-leugen/DoS), nooit toegang —
> commando's zonder geldige box-encryptie van een gepaird device worden
> genegeerd.

## 2. Pairing (eenmalig per client)

Doel: agent en client wisselen publieke sleutels uit en vertrouwen elkaar
daarna. Het relay bemiddelt maar leert alleen *dat* er gepaird is, niet meer.

1. Gebruiker klikt **Pair** in de mini-UI van de agent.
2. Agent genereert een eenmalige pairingcode (TTL 5 min) en toont een
   QR-code met: `relay-URL, agent_id, pairing_secret`.
3. Client scant de QR en stuurt via het relay een `pair_request` met een
   HMAC over zijn eigen publieke sleutel, gesleuteld met `pairing_secret`
   (bewijs van QR-bezit; het secret zelf gaat nooit over de lijn).
4. Agent verifieert de HMAC, toont ter bevestiging de device-naam in de
   mini-UI, en antwoordt met `pair_accept` (zijn publieke sleutel, idem
   geauthenticeerd).
5. Beide kanten slaan elkaars publieke sleutel op en deriveren per sessie
   een gedeelde sleutel (ECDH). De pairingcode is verbruikt.

Ontpairen kan aan beide kanten: agent-UI toont de lijst gepairde devices
met een verwijderknop; de client kan een agent vergeten.

## 3. Berichten (agent ↔ client, E2E via relay)

Envelop (leesbaar voor het relay, alleen voor routering):

```json
{ "to": "<agent_id | client_id>", "from": "<afzender-id>", "payload": "<E2E-versleuteld>" }
```

Payloads (na ontsleuteling):

| Type | Richting | Inhoud |
|---|---|---|
| `status` | agent → client | `machine_name`, `os`, `session: locked \| unlocked`, `ts` |
| `status_request` | client → agent | — |
| `lock` | client → agent | `nonce`, `ts` |
| `lock_result` | agent → client | `ok \| error`, `session`, `nonce` |

- **E2E-formaat** (geïmplementeerd): payload = `"e1:" + base64(nonce ‖
  NaCl-box)` — X25519 + XSalsa20-Poly1305, verse random nonce per bericht.
  De agent negeert stilzwijgend: sealed berichten van niet-gepairde
  afzenders, onontsleutelbare berichten, en élk plaintext commando (enige
  uitzondering: een geldige `pair_request` bij een open pairing-window).
- HMAC-constructie pairing: `HMAC-SHA256(secret, join("\n", label,
  afzender-id, pubkey-b64))` met label `pair_request` of `pair_accept`.
- De agent stuurt `status` bij elke lock/unlock-wissel (event-gedreven, geen
  polling op de pc) en als antwoord op `status_request`.
- "⚫ offline/uit" is geen bericht maar relay-kennis: de client vraagt het
  relay welke gepairde agents verbonden zijn.
- `nonce` + `ts` in `lock` beschermen tegen replay: de agent weigert oude
  timestamps en reeds geziene nonces.

## 4. Push (latere fase)

De killer feature — "je pc staat al 5 min onvergrendeld terwijl jij weg
bent" — vergt een actieve rol van het relay, want een PWA kan niet op de
achtergrond pollen:

1. Agent meldt statuswissels toch al aan het relay-kanaal (versleuteld; het
   relay ziet alleen *dat* er een event is, plus een door de agent bewust
   onversleuteld gezet vlagje `session`— dit is de enige inhoudelijke
   concessie en wordt pas gedaan als de gebruiker push aanzet).
2. Relay ziet: agent onvergrendeld én geen client verbonden → na X minuten
   Web Push naar de gepairde devices (werkt ook op iOS-PWA ≥ 16.4, mits op
   homescreen geïnstalleerd).

## Keuzes

Voorstellen na inkijk in de Tuuut-repo (fresh build, bewezen pipeline) —
bevestigen vóór de eerste regel code:

- **Client-stack: React + Vite + TS + vite-plugin-pwa + Capacitor** —
  beslist; zelfde pipeline als Tuuut. Het pairing-patroon (device-sleutelpaar
  via WebCrypto, gesigneerde requests met timestamp + nonce, kortlevende
  QR-tokens) bestaat daar al en wordt hier hergebruikt.
- **Agent: Go** (voorstel) — één statisch binary per OS, eenvoudige
  cross-compile Windows/Linux, tray-support; crypto via de
  libsodium-compatibele `golang.org/x/crypto`-familie (X25519/NaCl-box,
  matcht WebCrypto aan de clientkant).
- **Relay: FastAPI/Starlette-WebSockets op Cloud Run** (voorstel) — bekende
  deploy-flow van Tuuut/Cilantro. Aandachtspunten: de permanente
  agent-verbinding verhindert scale-to-zero (kost blijft verwaarloosbaar),
  en Cloud Run kapt een WSS-verbinding na max. 60 min — de agent moet dus
  stil en met backoff herverbinden (moet hij sowieso kunnen).
