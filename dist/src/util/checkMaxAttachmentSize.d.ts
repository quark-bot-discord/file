/**
 * Largest single file a bot or webhook can upload to a guild, by boost tier.
 * Each value sits just under Discord's limit: 20 MiB by default (3 Sep 2026,
 * previously 10 MiB), 50 MiB at tier 2, 100 MiB at tier 3.
 */
export declare function checkMaxAttachmentSize(premium_tier: number): number;
