export function checkMaxAttachmentSize(premium_tier: number): number {
  switch (premium_tier) {
    case 2:
      return 52420000;
    case 3:
      return 104840000;
    default:
      return 26110000;
  }
}
