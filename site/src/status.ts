// What each page status is called and what it means, for the badge and the
// sidebar. The wording of the llms.txt paragraph is in remark-status.mjs.
export const STATUSES = {
  target: {
    label: 'Target state',
    sidebar: 'Target',
    variant: 'note',
    hint: 'Describes the design; not built yet.',
  },
  partial: {
    label: 'Partly built',
    sidebar: 'Partial',
    variant: 'caution',
    hint: 'Describes the design; part of it is built and part is not.',
  },
  page: {
    label: 'Page complete',
    sidebar: 'Page',
    variant: 'default',
    hint: 'A page about the project itself. Complete; describes nothing that is built.',
  },
  shipped: {
    label: 'Shipped',
    sidebar: 'Shipped',
    variant: 'success',
    hint: 'Describes what has been built and released.',
  },
} as const;
