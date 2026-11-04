# Deploying the Decoy cloud (Cloudflare Worker + D1)

You need: a free Cloudflare account, Node 20+. Everything below runs from the `backend/` folder.

## Try it on your own computer first (no account needed)
```
node backend/dev-server.mjs
```
Then in the Decoy popup: More protection → Protect each other → paste `http://localhost:8787` → Save.
Emails are printed in that terminal instead of being sent. Data is lost when you stop it.

## Put it online
1. `npx wrangler login`  (opens a browser, log in to Cloudflare)
2. `npx wrangler d1 create decoy`  → copy the `database_id` it prints into `wrangler.toml`
3. `npx wrangler d1 migrations apply decoy --remote`
4. Secrets (made-up values stay on Cloudflare, never in the repo):
   - `npx wrangler secret put SALT`  → paste any long random string (used to hash network addresses)
   - `npx wrangler secret put RESEND_API_KEY`  → from resend.com (free tier is plenty)
5. `npx wrangler deploy`  → it prints your address, like `https://decoy-cloud.<you>.workers.dev`
6. Put that address in `wrangler.toml` as `PUBLIC_URL`, then `npx wrangler deploy` once more
   (the confirm links in emails use it).
7. Paste the address into the Decoy popup (More protection → Protect each other).

## Email
- Quick test: set `MAIL_FROM = "Decoy <onboarding@resend.dev>"`. Resend only delivers these to the email you signed up
  to Resend with, so use your own address as the "trusted person" while testing.
- Real use: add and verify a domain in Resend, then use `alerts@your-domain`.

## What the server stores
- Random install id + a hash of its secret key (no name, no email).
- A hash of the network address, only to count "different people" (not stored in readable form).
- Reports: site address + finding type + time. Nothing the person typed.
- Trusted people: the invited person's email and name until they are removed or say "No thanks". Removing wipes the email.
  "No thanks" keeps only a hash of the email so they are never asked again.
- Alert log: site address, kind, time. No page content.

## Limits that are built in
Installs 10/day per network · reports 20/day per install · invites 5/day per install and 2/day per email ·
3 trusted people max · alerts 10/day, and the same site only once an hour unless details were typed ·
a site is listed only after 3 different networks confirm it (installs must be an hour old).

## Later
`*.workers.dev` is treated by Decoy's own scanner as a place scam kits use, so move to a custom domain before sharing widely.
