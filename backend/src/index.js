import { handle } from "./app.js";
export default { fetch: (req, env) => handle(req, env) };
