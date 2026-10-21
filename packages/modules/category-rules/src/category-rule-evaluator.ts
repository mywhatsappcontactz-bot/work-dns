import {
  BaseRule,
  IRuleEvaluator,
  PolicyContext,
  RuleEvaluationResult,
} from '@work-dns/shared-types';
import { normalizeDomain, matchesDomainPattern } from '@work-dns/policy-engine';

export interface CategoryRule extends BaseRule {
  type: 'category_rule';
  category: 'social_media' | 'gambling' | 'streaming' | 'adult';
  effect: 'ALLOW' | 'BLOCK';
}

export const CATEGORY_DOMAINS: Record<CategoryRule['category'], string[]> = {
  social_media: [
    'facebook.com',
    '*.facebook.com',
    'fb.com',
    'instagram.com',
    '*.instagram.com',
    'tiktok.com',
    '*.tiktok.com',
    'twitter.com',
    '*.twitter.com',
    'x.com',
    '*.x.com',
    'reddit.com',
    '*.reddit.com',
  ],
  gambling: [
    'bet9ja.com',
    '*.bet9ja.com',
    'sportybet.com',
    '*.sportybet.com',
    '1xbet.com',
    '*.1xbet.com',
    'nairabet.com',
    '*.nairabet.com',
    'betway.com',
    '*.betway.com',
  ],
  streaming: [
    'netflix.com',
    '*.netflix.com',
    'youtube.com',
    '*.youtube.com',
    'hulu.com',
    '*.hulu.com',
    'disneyplus.com',
    '*.disneyplus.com',
    'twitch.tv',
    '*.twitch.tv',
  ],
  adult: [
    'pornhub.com',
    '*.pornhub.com',
    'xvideos.com',
    '*.xvideos.com',
  ],
};

export class CategoryRuleEvaluator implements IRuleEvaluator<CategoryRule> {
  public readonly ruleType = 'category_rule';

  public matches(rule: CategoryRule, context: PolicyContext): boolean {
    if (rule.type !== 'category_rule') return false;

    const domainList = CATEGORY_DOMAINS[rule.category] ?? [];
    const normalizedQueried = normalizeDomain(context.queriedDomain);

    return domainList.some((pattern) => matchesDomainPattern(pattern, normalizedQueried));
  }

  public evaluate(rule: CategoryRule, context: PolicyContext): RuleEvaluationResult {
    const isMatched = this.matches(rule, context);
    if (!isMatched) {
      return { matched: false };
    }

    return {
      matched: true,
      action: rule.effect,
      reasonCode: `CATEGORY_${rule.category.toUpperCase()}_${rule.effect}`,
    };
  }
}
