/**
 * Arranges files into groups of a maximum size. Needed for when files are bulk deleted, and many must be sent
 * @param {Attachment[]} inputs Array of attachments to sort
 * @param {Number} maxSize Maximum total size of a group of files
 * @returns {Attachment[][]} Groups of attachments
 */
export default function sortFiles(inputs, maxSize) {
  inputs.sort((a, b) => b.size - a.size);
  let result = [];
  while (inputs.length) {
    let groups = [];
    let sum = inputs[0].size;
    groups.push(inputs[0]);
    inputs.splice(0, 1);
    let j = 0;
    while (j < inputs.length && sum < maxSize && groups.length < 10) {
      if (inputs[j].size + sum <= maxSize) {
        sum += inputs[j].size;
        groups.push(inputs[j]);
        inputs.splice(j, 1);
      } else {
        j++;
      }
    }
    result.push(groups);
  }
  return result;
}
