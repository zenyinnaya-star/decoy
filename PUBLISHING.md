# Publishing Decoy so updates go live automatically

Chrome updates installed extensions by itself, but only ones that came from the Chrome Web Store.
Loading the `dist` folder by hand ("unpacked") never auto-updates.

## One time
1. Chrome Web Store developer account: https://chrome.google.com/webstore/devconsole (one-time $5 fee).
2. Build and zip: `npm run build`, then zip the contents of `dist/` (manifest.json must be at the top of the zip).
3. In the dashboard: New item, upload the zip, fill in the listing (description, screenshots, icon 128).
   - Privacy tab: say what is collected. Decoy sends nothing anywhere unless the user turns on the optional cloud features. Add a privacy policy URL.
   - Permission justifications (they ask for each): activeTab, scripting (scan pages opened before install), storage, alarms, contextMenus, declarativeNetRequest (tracker and ad blocking), optional downloads and notifications, and the `http/https/file` page access (scan the page you are on).
4. Submit for review. First review usually takes days.
5. Copy the item's ID (the 32 letters in its URL).

## API access for GitHub (one time)
Follow https://github.com/fregante/chrome-webstore-upload-keys to get a client id, client secret and refresh token.
Then in the GitHub repo: Settings, Secrets and variables, Actions, add:
`CWS_EXTENSION_ID`, `CWS_CLIENT_ID`, `CWS_CLIENT_SECRET`, `CWS_REFRESH_TOKEN`.
Never put these in the code.

## Every update
1. Raise `version` in `static/manifest.json` (the store rejects a repeat version).
2. Commit and push, then tag: `git tag v0.9.0 && git push origin v0.9.0`.
3. The workflow builds, runs the tests, uploads and submits. Google reviews it (hours to a few days), then everyone's Chrome updates itself.

Pushing to `main` alone does not publish: every submit goes to review, so it only runs on a tag (or the "Run workflow" button).
