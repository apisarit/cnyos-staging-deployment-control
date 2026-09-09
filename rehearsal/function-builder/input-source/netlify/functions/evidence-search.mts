import { handleEvidenceSearch } from './_shared/evidence-search.mjs';

export default async (request, context) => handleEvidenceSearch(request, context, {
  getEnv: name => Netlify.env.get(name) || ''
});

export const config = {
  path: '/api/evidence-search',
  method: 'POST',
  rateLimit: {
    windowLimit: 12,
    windowSize: 60,
    aggregateBy: ['ip', 'domain']
  }
};
