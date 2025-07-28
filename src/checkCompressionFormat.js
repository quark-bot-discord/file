export function checkCompressionFormat(timestamp) {
  if (timestamp < 1754002800) {
    return "gzip";
  }
  return "zstd";
}
