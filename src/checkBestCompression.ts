import { CompressionMode } from "./compressData";

export function checkBestCompression(mimeType: string): CompressionMode {
  if (!mimeType) return "brotli";

  // normalize (strip params, lowercase)
  const mt = mimeType.split(";")[0].trim().toLowerCase();

  switch (mt) {
    // --- Image types that are already compressed (no benefit) ---
    case "image/jpeg":
    case "image/jpg":
    case "image/png":
    case "image/gif":
    case "image/webp":
    case "image/avif":
    case "image/heif":
    case "image/heic":
    case "image/x-icon":
    case "image/vnd.microsoft.icon":
      // vector images (SVG is text — compress)
      return "none";

    // --- Video/container formats (already compressed) ---
    case "video/mp4":
    case "video/webm":
    case "video/quicktime":
    case "video/x-matroska":
    case "video/x-msvideo":
    case "application/ogg":
    case "video/ogg":
    case "application/vnd.apple.mpegurl":
      return "none";

    // --- Audio formats (already compressed) ---
    case "audio/mpeg":
    case "audio/mp3":
    case "audio/aac":
    case "audio/ogg":
    case "audio/wav":
    case "audio/opus":
    case "audio/flac":
    case "audio/webm":
      return "none";

    // --- Archives & compressed containers ---
    case "application/zip":
    case "application/x-zip-compressed":
    case "application/x-7z-compressed":
    case "application/x-rar-compressed":
    case "application/gzip":
    case "application/x-gzip":
    case "application/x-tar":
    case "application/x-bzip2":
      return "none";

    // --- Fonts (often already compressed but small gains are possible) ---
    case "font/woff":
    case "font/woff2":
    case "font/ttf":
    case "font/otf":
      return "none";

    // --- Executables / binaries (don't compress) ---
    case "application/x-msdownload":
    case "application/vnd.microsoft.portable-executable":
    case "application/x-executable":
    case "application/vnd.android.package-archive":
      return "none";

    // --- Text-like formats which compress very well with Brotli ---
    case "text/plain":
    case "text/html":
    case "text/css":
    case "text/csv":
    case "text/javascript":
    case "application/javascript":
    case "application/ecmascript":
    case "application/json":
    case "application/xml":
    case "text/xml":
    case "application/rtf":
    case "application/wasm":
    case "image/svg+xml":
    case "application/pdf":
    case "application/vnd.ms-excel":
    case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
    case "application/msword":
    case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
    case "application/vnd.ms-powerpoint":
    case "application/vnd.openxmlformats-officedocument.presentationml.presentation":
      return "brotli";

    // --- Generic categories ---
    // text/* -> compress
    default: {
      if (mt.startsWith("text/")) return "brotli";
      if (mt.startsWith("application/")) {
        // many application/* are structured text (JSON, XML, JS) — default to Brotli
        return "brotli";
      }
      // conservative default: compress
      return "brotli";
    }
  }
}