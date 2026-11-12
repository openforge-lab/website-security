# Privacy & compliance quick pass

Short checks after the 7 doors. These are about customer trust and the law, which depend on where the business and its users are — flag what needs a lawyer or accountant rather than giving legal conclusions.

1. **Recording & tracking tools** — list analytics, session-recording (Hotjar, Clarity, FullStory, LogRocket), chat widgets and pixels, and which companies get the data. Do trackers that need consent load before the visitor chooses? Do recordings mask passwords, payment fields and private text?
2. **Cookie / consent banner** — if one is required for the users' locations, "Reject" must work as well as "Accept" and actually block the trackers.
3. **Privacy page accuracy** — compare what the app actually collects and which services receive it with the privacy page and terms. Flag copied policies that describe tools the app doesn't use, or miss ones it does. A contact address should exist.
4. **Marketing emails** — working unsubscribe link, sender details/address in the footer, unsubscribed people excluded from later sends. Receipts and password resets are separate from marketing.
5. **Marketing SMS** — a phone number given for login codes is not permission for promotions; consent recorded separately; STOP works.
6. **Account & data deletion** — can a user delete their account and data, or at least request it?
7. **Accessibility basics** — signup, the main task and checkout usable with keyboard only; form fields have labels; visible focus; readable contrast; buttons have names. Use WCAG 2.1 AA as the reference; say what needs a human tester.
8. **Tax** — who calculates, collects and pays sales tax / VAT on sales (e.g. Stripe Tax on/off, merchant-of-record like Lemon Squeezy/Paddle vs. the owner). List questions for an accountant; never assume the payment provider handles everything.

## Israel-specific (when the business or users are in Israel)
- **Privacy Protection Law, Amendment 13 (in force Aug 2025)** and the Data Security Regulations: a serious data exposure (e.g. door 3 or 4 open on real customer data) may have to be reported to the Privacy Protection Authority; databases may need a security level and documented access controls. Flag for a lawyer — don't conclude.
- **Spam law (Communications Law §30A):** marketing email/SMS needs prior explicit consent, the word "פרסומת" at the start of the subject/message, sender details and an easy opt-out.
- **Accessibility (Israeli Standard 5568, based on WCAG 2.0 AA):** most businesses serving the public need an accessible site and an accessibility statement page.
- **Tax:** Israeli VAT on sales; tax invoices/receipts must be issued (often via an approved invoicing service). Questions for an accountant.

## What code alone can't show
Trackers firing before consent, cookie-banner behavior, real email footers and whether STOP/unsubscribe actually works need the live site or the email/SMS provider. Mark those 🟠 "לא נבדק" when you only have code.

Report each as 🔴 / 🟠 / 🟢 with one plain sentence (🟠 also for "couldn't check from code"). Never edit policies, consent settings, mailing lists or tax settings during the audit.
