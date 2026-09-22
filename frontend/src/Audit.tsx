import { AuditProvider, AuditView } from "@truvity/audit/react";

import { audit } from "./api";
import { roster } from "./auditSentences";
import { paths } from "./router";
import { Nothing, Page } from "./ui";

const sentences = [roster];

/** The audit trail, as the connected installation keeps it.
 *
 *  The installation's own view: its profiles along the top, the ones this
 *  person may read (the installation says which); the qualifier box; and
 *  every record as the sentence access-roster's catalogue gives it. The
 *  console only carries the calls, with a token for the person, so what
 *  anyone sees here is decided by the installation's grants and every
 *  read is itself recorded there. */
export function AuditPage({ query, connected }: { query?: URLSearchParams; connected: boolean }) {
  return (
    <Page
      title="Audit"
      lede="What happened: sign-ins, token exchanges, connects and every change to GitHub, kept by the audit installation."
    >
      {connected ? (
      <AuditProvider client={audit} sentences={sentences}>
        <AuditView
          query={query?.get("q") ?? ""}
          {...(query?.get("profile") ? { profile: query.get("profile") ?? "" } : {})}
          permalink={(profile, id) => `#${paths.audit(`id:${id}`, profile)}`}
        />
      </AuditProvider>
      ) : (
        <Nothing>
          No audit installation is connected to this console, so nothing is kept beyond the service's log. Set audit.writer,
          audit.query to connect one.
        </Nothing>
      )}
    </Page>
  );
}
