// What the home page says, as data. Every claim about a vendor is one that a page of these
// docs states: the GitHub and Slack ceremonies and Google delegation on
// /integrations/connecting/, the Cloudflare minting token on /integrations/cloudflare/,
// the AWS provider limit on /integrations/connecting/#aws-oidc-provider-and-role-trust.

export interface Chip {
  name: string;
  /** A name in the sprite (marks.ts, or a glyph in Marks.astro). Absent for a text-only chip. */
  mark?: string;
  /** What is hard, in one short sentence. */
  note: string;
  /** Whether the mark is a brand mark, as opposed to a plain glyph. */
  brand?: boolean;
  /** The few words under which the first screen shows this chip, when it is one of the heaviest. */
  band?: string;
}

// Pain 1: every system has its own place to say who may come in.
export const fragmented: Chip[] = [
  { name: 'AWS', note: 'An identity provider and a trust policy in every account.' },
  { name: 'Google Cloud', mark: 'googlecloud', brand: true, note: 'Its own project, its own consent screen.' },
  { name: 'GitHub', mark: 'github', brand: true, note: 'Single sign-on per organisation. CI uses Apps and tokens instead.' },
  { name: 'GitLab', mark: 'gitlab', brand: true, note: 'A second git host, a second sign-in to set up.' },
  { name: 'Slack', note: 'Sign-in is one setting. Bots and apps are another.' },
  { name: 'CI jobs', mark: 'githubactions', brand: true, note: 'Secrets copied into each pipeline.' },
  { name: 'PostgreSQL', mark: 'postgresql', brand: true, note: 'Roles and passwords inside each database.' },
  { name: 'Kubernetes', mark: 'kubernetes', brand: true, note: 'OIDC settings on every API server.' },
  { name: 'SSH hosts', mark: 'terminal', note: 'authorized_keys on every host.' },
  { name: 'Argo CD', mark: 'argo', brand: true, note: 'A login of its own, with groups mapped by hand.' },
  { name: 'Grafana', mark: 'grafana', brand: true, note: 'Another login, another group mapping.' },
  { name: 'Team wiki', mark: 'page', note: 'Accounts kept apart from the directory.' },
];

// Pain 2: the setup that should be code is a ceremony in a web console.
export const ceremonies: Chip[] = [
  { name: 'GitHub App', mark: 'github', brand: true, band: 'click-through', note: 'Created in a web form that an owner confirms. There is no API to change its permissions later.' },
  { name: 'Slack app', band: 'reinstall for a scope', note: 'No one-click flow. A configuration token lasts 12 hours, and a new scope means a reinstall.' },
  { name: 'Cloudflare', mark: 'cloudflare', brand: true, band: 'no STS', note: 'No STS: no native way to trade an identity for a short-lived, scoped API token. The token that makes tokens is created by hand.' },
  { name: 'Google Workspace', mark: 'google', brand: true, band: 'delegation by hand', note: 'Domain-wide delegation is granted by a Super Admin in the console, by client id.' },
  { name: 'Google OAuth consent', mark: 'googlecloud', brand: true, note: 'In testing mode, refresh tokens expire after seven days.' },
  { name: 'AWS IAM', band: 'a provider per account', note: 'One OIDC provider per account and a trust policy per role. At most 100 providers per account.' },
  { name: 'Team wiki', mark: 'page', note: 'No service accounts: the API key belongs to a person.' },
  { name: 'On-call tool', mark: 'bell', note: 'A key that an administrator creates by hand.' },
  { name: 'Service-account keys', mark: 'key', note: 'Long-lived keys to rotate, or forbidden by policy.' },
  { name: 'Console settings', mark: 'drift', note: 'Set by hand, so they drift from what was reviewed.' },
];

export interface Link {
  text: string;
  href: string;
}

// What sluis does about each pain, and where to read it.
export const answers = {
  sso: {
    heading: 'One sign-in, trusted everywhere',
    text: 'People sign in through the identity provider that already knows them, such as Google Workspace or any OpenID Connect provider. sluis issues the tokens, and AWS, Kubernetes, PostgreSQL, SSH and your applications each get one short trust entry for sluis instead of a login of their own.',
    links: [
      { text: 'Integrations', href: '/integrations/' },
      { text: 'Google Workspace', href: '/integrations/google-workspace/' },
      { text: 'Generic OIDC', href: '/integrations/oidc-upstream/' },
      { text: 'AWS', href: '/integrations/aws/' },
      { text: 'Kubernetes', href: '/integrations/kubernetes/' },
      { text: 'PostgreSQL', href: '/integrations/postgresql/' },
      { text: 'SSH', href: '/integrations/ssh/' },
      { text: 'Applications', href: '/integrations/applications/' },
    ] satisfies Link[],
  },
  code: {
    heading: 'Declared in a reviewed file, checked for drift',
    text: 'Each integration is declared as data. sluis runs the vendor ceremony once, keeps what comes back sealed, compares what was granted with what was declared, and does nothing until the integration is enabled. Where a vendor has no STS, sluis plays that part: a job trades its identity for a token that lasts minutes and reaches one repository, one zone or one bucket.',
    links: [
      { text: 'Connecting integrations', href: '/integrations/connecting/' },
      { text: 'GitHub', href: '/integrations/github/' },
      { text: 'Cloudflare', href: '/integrations/cloudflare/' },
      { text: 'Slack and more', href: '/integrations/more/' },
      { text: 'The local installation', href: '/runtimes/local/' },
    ] satisfies Link[],
  },
};

// The six properties of sluis's side of the chain, each with the page that owns the fact.
export const secure: { name: string; href: string }[] = [
  { name: 'Intermediates only', href: '/principles/#what-sluis-is-and-is-not' },
  { name: 'Keys born in their store', href: '/principles/#1-a-key-is-born-in-its-store-and-never-leaves-it' },
  { name: 'No tenant authority keys', href: '/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule' },
  { name: 'A signed audit trail', href: '/concepts/audit/' },
  { name: 'Short-lived credentials', href: '/concepts/identity/' },
  { name: 'Verify, never trust', href: '/principles/#4-verify-never-trust-a-claim' },
];

// The sixteen principles of docs/principles.md, in its order, with who shares each.
export const principles: { n: number; name: string; href: string; who: 'shared' | 'part' | 'sluis' }[] = [
  { n: 1, name: 'A key is born in its store and never leaves it', href: '#1-a-key-is-born-in-its-store-and-never-leaves-it', who: 'shared' },
  { n: 2, name: 'Trust is layered, and redundancy is not a defence against compromise', href: '#2-trust-is-layered-and-redundancy-is-not-a-defence-against-compromise', who: 'shared' },
  { n: 3, name: 'Keys are shared, rotated and given to tenants by rule', href: '#3-keys-are-shared-rotated-and-given-to-tenants-by-rule', who: 'part' },
  { n: 4, name: 'Verify; never trust a claim', href: '#4-verify-never-trust-a-claim', who: 'shared' },
  { n: 5, name: 'Open standards, as their consumers implement them', href: '#5-open-standards-as-their-consumers-implement-them', who: 'part' },
  { n: 6, name: 'Generic products, joined by a contract', href: '#6-generic-products-joined-by-a-contract', who: 'shared' },
  { n: 7, name: 'A person only where a person adds safety', href: '#7-a-person-only-where-a-person-adds-safety', who: 'shared' },
  { n: 8, name: 'Nothing without a consumer', href: '#8-nothing-without-a-consumer', who: 'shared' },
  { n: 9, name: 'Measure before deciding, and date the measurement', href: '#9-measure-before-deciding-and-date-the-measurement', who: 'shared' },
  { n: 10, name: 'Public by default, private where it protects', href: '#10-public-by-default-private-where-it-protects', who: 'shared' },
  { n: 11, name: 'One product, many installations', href: '#11-one-product-many-installations', who: 'sluis' },
  { n: 12, name: 'A loosening is temporary, a tightening is durable', href: '#12-a-loosening-is-temporary-a-tightening-is-durable', who: 'sluis' },
  { n: 16, name: 'Few credential holders', href: '#16-few-credential-holders', who: 'sluis' },
  { n: 17, name: 'Where a thing is written decides its class', href: '#17-where-a-thing-is-written-decides-its-class', who: 'sluis' },
  { n: 18, name: 'Plaintext lives only where it is used, behind two independent checks', href: '#18-plaintext-lives-only-where-it-is-used-behind-two-independent-checks', who: 'sluis' },
  { n: 19, name: 'One model, many transports', href: '#19-one-model-many-transports', who: 'sluis' },
];

// The first screen: the three pains side by side, each with its one-line headline, a
// sentence, and the heaviest of its chips. The full clouds and the chain are below it;
// `target` is the section that holds the whole of each.
export const band = {
  sso: {
    target: '#fragmented',
    headline: 'SSO stops at each product\u2019s edge',
    text: 'Cloud consoles, git, chat, CI, databases, Kubernetes and SSH each have their own login setup, and no one product covers them all.',
    // The names of the chips of `fragmented` shown here; the rest is counted.
    chips: ['AWS', 'GitHub', 'Slack', 'Kubernetes', 'PostgreSQL', 'SSH hosts'],
  },
  code: {
    target: '#as-code',
    headline: 'An identity provider is hard to run as code',
    text: 'The basics cost extra, the setup is fragile, and integrations are click-through ceremonies in a web console.',
  },
  root: {
    target: '#no-root',
    headline: 'Where does the root key live?',
    text: 'For certificates, SSH and release signing, few small setups can say where the root key lives and who can use it.',
    chain: [
      { name: 'ritueel', role: 'the root of custody' },
      { name: 'sluis', role: 'identity, tokens, certificates, audit' },
      { name: 'Your systems', role: 'cloud, git, chat, CI, databases, SSH' },
    ],
  },
};
