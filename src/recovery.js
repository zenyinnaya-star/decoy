// D15: "I already entered something". Plain steps by what was given.
export const GIVEN = [
  ["password", "A password"], ["card", "Card number"], ["ssn", "SIN / SSN"], ["id", "ID or passport photo"],
  ["code", "A one-time code"], ["nothing", "Nothing yet, I just clicked"],
];
const STEPS = {
  password: ["Change that password now, on the real site (type its address yourself).", "Change it anywhere else you reused it. Use a password manager so each site is different.", "Turn on two-step login (an authenticator app, not SMS) for email and banking first."],
  card: ["Call the number on the back of your card and say the card was exposed. They will block it and send a new one.", "Check recent transactions and dispute any you don't recognise.", "Watch statements for the next 2-3 months."],
  ssn: ["Put a fraud alert on your file at both credit bureaus (Equifax and TransUnion in Canada; Equifax, Experian and TransUnion in the US). Consider a credit freeze.", "Report it: Canadian Anti-Fraud Centre (1-888-495-8501) in Canada, IdentityTheft.gov in the US.", "Be careful with calls/emails about your tax or benefits accounts for a while."],
  id: ["Report the ID as exposed to the office that issued it and ask what to do.", "Put a fraud alert on your credit file at the credit bureaus.", "Report it to the Canadian Anti-Fraud Centre (Canada) or IdentityTheft.gov (US)."],
  code: ["A one-time code lets them into the account right now. Go to the real site and sign out of all devices.", "Change the password, then check recovery email/phone were not changed.", "Never read codes out to anyone who contacted you."],
  nothing: ["Close the tab. Don't enter anything else.", "If you downloaded or ran a file, run a full scan with your antivirus.", "You're fine. Decoy's test mode is a safe way to check a form next time."],
};
export function buildChecklist(kinds) {
  const ks = (kinds || []).filter((k) => STEPS[k]);
  const want = ks.length && !(ks.length === 1 && ks[0] === "nothing") ? ks.filter((k) => k !== "nothing") : ["nothing"];
  const out = [];
  for (const k of want) for (const s of STEPS[k]) if (!out.includes(s)) out.push(s);
  if (want[0] !== "nothing") out.push("Don't answer calls or texts that mention this. Scammers follow up.");
  return out;
}
