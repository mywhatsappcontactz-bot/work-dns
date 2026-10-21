import { DomainAllowRule } from '@work-dns/shared-types';

export interface TemplateDefinition {
  id: string;
  name: string;
  description: string;
  domains: string[];
}

export const STARTER_TEMPLATES: Record<string, TemplateDefinition> = {
  google_workspace: {
    id: 'google_workspace',
    name: 'Google Workspace',
    description: 'Allows Gmail, Google Docs, Drive, Meet, Calendar, and necessary Google APIs',
    domains: [
      'google.com',
      '*.google.com',
      'googleapis.com',
      '*.googleapis.com',
      'gstatic.com',
      '*.gstatic.com',
      'googleusercontent.com',
      '*.googleusercontent.com',
      'gmail.com',
      '*.gmail.com',
      'youtube.com',      // Meet avatars & embedded media
      '*.youtube.com',
      'ggpht.com',        // User avatars
      '*.ggpht.com',
    ],
  },
  microsoft_365: {
    id: 'microsoft_365',
    name: 'Microsoft 365 & Teams',
    description: 'Allows Outlook, Teams, OneDrive, SharePoint, and Office online services',
    domains: [
      'microsoft.com',
      '*.microsoft.com',
      'office.com',
      '*.office.com',
      'office365.com',
      '*.office365.com',
      'live.com',
      '*.live.com',
      'microsoftonline.com',
      '*.microsoftonline.com',
      'sharepoint.com',
      '*.sharepoint.com',
      'msftauth.net',
      '*.msftauth.net',
      'skype.com',
      '*.skype.com',
      'teams.microsoft.com',
    ],
  },
  slack: {
    id: 'slack',
    name: 'Slack Collaboration',
    description: 'Allows Slack messaging, calls, file uploads, and web client',
    domains: [
      'slack.com',
      '*.slack.com',
      'slack-edge.com',
      '*.slack-edge.com',
      'slack-core.com',
      '*.slack-core.com',
      'slack-imgs.com',
      '*.slack-imgs.com',
    ],
  },
  zoom: {
    id: 'zoom',
    name: 'Zoom Video Communications',
    description: 'Allows Zoom meetings, webinars, and desktop client connection',
    domains: [
      'zoom.us',
      '*.zoom.us',
      'zoom.com',
      '*.zoom.com',
      'zoomgov.com',
      '*.zoomgov.com',
    ],
  },
};

/**
 * Converts a starter template into an array of concrete DomainAllowRule instances.
 */
export function compileTemplateToRules(templateId: string, startPriority = 100): DomainAllowRule[] {
  const template = STARTER_TEMPLATES[templateId];
  if (!template) {
    throw new Error(`Unknown starter template: ${templateId}`);
  }

  return template.domains.map((pattern, index) => ({
    id: `template-${templateId}-${index}`,
    type: 'domain_allow',
    pattern,
    effect: 'ALLOW',
    priority: startPriority + index,
    description: `Allowed by template: ${template.name}`,
  }));
}
