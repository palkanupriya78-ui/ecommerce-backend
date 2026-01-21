const nodemailer = require("nodemailer");

const host = process.env.SMTP_HOST;
const port = Number(process.env.SMTP_PORT || 587);
const secure = String(process.env.SMTP_SECURE) === "true";
const user = process.env.SMTP_USER;
const pass = process.env.SMTP_PASS;
const from = process.env.EMAIL_FROM || "no-reply@example.com";

if (!host || !user || !pass) {
  throw new Error("SMTP env missing: SMTP_HOST/SMTP_USER/SMTP_PASS");
}
console.log("SMTP_HOST:", process.env.SMTP_HOST);
console.log("SMTP_PORT:", process.env.SMTP_PORT);
console.log("SMTP_SECURE:", process.env.SMTP_SECURE);
console.log("SMTP_USER:", process.env.SMTP_USER);
console.log("SMTP_PASS length:", (process.env.SMTP_PASS || "").length);

const transporter = nodemailer.createTransport({
  host,
  port,
  secure,
  auth: { user, pass },
  // ✅ Brevo/STARTTLS on 587
  requireTLS: true,
});

transporter.verify().then(
  () => console.log("📧 SMTP ready:", { host, port, secure, user }),
  (err) => console.error("SMTP verify failed:", err.message, { host, port, secure, user })
);

async function sendEmail({ to, subject, html, text }) {
  if (!to) throw new Error("Recipient 'to' is required");
  return transporter.sendMail({ from, to, subject, html, text });
}

module.exports = { sendEmail };