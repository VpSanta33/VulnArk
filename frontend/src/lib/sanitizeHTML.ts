import DOMPurify from 'dompurify';

// Apply this at render time so historical articles receive the same protection.
export function sanitizeHTML(content: string): string {
  return DOMPurify.sanitize(content, {
    USE_PROFILES: { html: true },
    FORBID_TAGS: ['style', 'form', 'input', 'button', 'textarea', 'select', 'iframe', 'object', 'embed'],
    FORBID_ATTR: ['style', 'srcset'],
    SANITIZE_NAMED_PROPS: true,
  });
}
