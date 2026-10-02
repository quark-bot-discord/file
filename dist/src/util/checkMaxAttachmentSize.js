/**
 * Largest single file a bot or webhook can upload to a guild, by boost tier.
 * Each value sits just under Discord's limit: 20 MiB by default (3 Sep 2026,
 * previously 10 MiB), 50 MiB at tier 2, 100 MiB at tier 3.
 */
export function checkMaxAttachmentSize(premium_tier) {
    switch (premium_tier) {
        case 2:
            return 52420000;
        case 3:
            return 104840000;
        default:
            return 20960000;
    }
}
//# sourceMappingURL=checkMaxAttachmentSize.js.map