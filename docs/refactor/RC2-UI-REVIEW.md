# RC2 prototype fidelity and functional review

The approved reference is the November 6 lilac NestLink prototype, including its original linked-N logo, 214 px sidebar, 76 px compact rail, typography, surfaces and action hierarchy. `config/ui-tokens.json` remains the color and spacing source. Comparable products inform task grouping; their visual identities do not replace this reference.

Reference review on November 12:

| Reference | Relevant pattern | Application in NestLink |
| --- | --- | --- |
| [RustDesk client documentation](https://rustdesk.com/docs/en/client/) | Remote connection as the primary task; network/server configuration in Settings | Entry is focused on server connection and sign-in; diagnostics moved out of login |
| [NetBird official project overview](https://github.com/netbirdio/netbird/blob/main/README.md) | Distinguishes peers, management, access policies and activity logging | Space membership and managed networks have explicit pages; account sign-ins remain separate from registered hosts |
| [frp documentation](https://gofrp.org/en/docs/) | Explicit service and proxy configuration | Tunnels retain protocol, target, ingress and authorization rather than presenting saved definitions as verified reachability |

These are documentation references, not claims of interactive audits of their deployed dashboards. The local review copies are outside the repository; the links identify the consulted sources.

RC2 fixes the login omission in RC1's synthetic frame inventory. The native exporter adds connection, sign-in and sign-in error in light, dark and small layouts. A regression deliberately retains a cached principal while signed out and rejects any settings or old setup heading on the entry screen.

Web follows the prototype's main/admin navigation, lavender sidebar, split entry, space list and four space tabs, login-device cards and application confirmation dialogs. Existing real backend actions remain bound to typed SDK calls. Chrome, Edge and Firefox integration now additionally require actual independent sign-ins, cancellation without DELETE, a confirmed other-session DELETE, account readback, rejection of that revoked browser and continued access by the controller. The evidence verifier requires every proof field and the exact helper hash.

Review status before hosted execution: source, formatter/parser and tool-contract checks only. Actual native/Web build, browser integration, final frame inspection and fixed local Windows runtime verification remain required. No pixel-perfect or full-functionality pass is implied by this source review. Final results must bind the exact RC2 commit and candidate; RC1 results cannot qualify RC2.

Historical remote-network, hardware, signing and long-duration acceptance retains its recorded status in `config/rc-deferred-acceptance.json`. RC2 development tests do not rewrite those outcomes.
