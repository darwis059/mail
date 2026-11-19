# On-premises Exchange mail

Choose **Microsoft Exchange (EWS)** when adding an account. Enter your email address, Exchange username and password, and the full EWS endpoint. For PLN, use `https://webmail.pln.co.id/EWS/Exchange.asmx` and **Auto** or **NTLM** authentication.

A bare username uses the default domain (initially `pusat`). You can enter `DOMAIN\user` to specify a domain explicitly, or enter a UPN such as `user@example.com` to use the full username. Auto prefers NTLM and uses Basic if that is the only supported option the server offers. The password is stored in your system credential store. Use HTTPS with a certificate trusted by your system.

Flectar checks for new mail every 30 seconds by default. Exchange saves submitted mail in Sent Items. Flectar uses the configured mail history limit when downloading messages. Server search and Exchange calendar and contacts are outside this mail integration.

Create and rename Exchange folders in webmail. To upload mail from an archive, import it into Local Mail, then transfer messages to an existing Exchange folder.
