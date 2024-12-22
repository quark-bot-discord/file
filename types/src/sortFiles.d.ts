/**
 * Arranges files into groups of a maximum size. Needed for when files are bulk deleted, and many must be sent
 * @param {Attachment[]} inputs Array of attachments to sort
 * @param {Number} maxSize Maximum total size of a group of files
 * @returns {Attachment[][]} Groups of attachments
 */
export default function sortFiles(inputs: Attachment[], maxSize: number): Attachment[][];
