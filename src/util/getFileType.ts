export function getFileType(url: string, contentType?: string | null): string {
  // Prefer Content-Type header
  if (contentType) {
    return contentType.split(';')[0].trim().toLowerCase();
  }
  
  // Fallback to file extension
  const ext = url.split('.').pop()?.toLowerCase() || '';
  const extToMime: { [key: string]: string } = {
    // images
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    png: 'image/png',
    gif: 'image/gif',
    webp: 'image/webp',
    avif: 'image/avif',
    heif: 'image/heif',
    heic: 'image/heic',
    svg: 'image/svg+xml',
    bmp: 'image/bmp',
    ico: 'image/x-icon',
    cur: 'image/x-icon',
    tif: 'image/tiff',
    tiff: 'image/tiff',
    // video
    mp4: 'video/mp4',
    m4v: 'video/x-m4v',
    webm: 'video/webm',
    mkv: 'video/x-matroska',
    mov: 'video/quicktime',
    avi: 'video/x-msvideo',
    mpg: 'video/mpeg',
    mpeg: 'video/mpeg',
    ts: 'video/mp2t',
    m2ts: 'video/mp2t',
    // audio
    mp3: 'audio/mpeg',
    m4a: 'audio/mp4',
    aac: 'audio/aac',
    wav: 'audio/wav',
    ogg: 'audio/ogg',
    oga: 'audio/ogg',
    opus: 'audio/opus',
    flac: 'audio/flac',
    amr: 'audio/amr',
    // text
    txt: 'text/plain',
    text: 'text/plain',
    csv: 'text/csv',
    html: 'text/html',
    htm: 'text/html',
    css: 'text/css',
    js: 'application/javascript',
    mjs: 'application/javascript',
    json: 'application/json',
    xml: 'application/xml',
    yml: 'application/x-yaml',
    yaml: 'application/x-yaml',
    md: 'text/markdown',
    markdown: 'text/markdown',
    rtf: 'application/rtf',
    // fonts
    woff: 'font/woff',
    woff2: 'font/woff2',
    ttf: 'font/ttf',
    otf: 'font/otf',
    eot: 'application/vnd.ms-fontobject',
    // archives / compressed
    zip: 'application/zip',
    tar: 'application/x-tar',
    gz: 'application/gzip',
    tgz: 'application/gzip',
    bz2: 'application/x-bzip2',
    '7z': 'application/x-7z-compressed',
    rar: 'application/x-rar-compressed',
    // executables / installers
    exe: 'application/x-msdownload',
    dll: 'application/x-msdownload',
    deb: 'application/x-debian-package',
    rpm: 'application/x-rpm',
    apk: 'application/vnd.android.package-archive',
    dmg: 'application/x-apple-diskimage',
    iso: 'application/x-iso9660-image',
    bin: 'application/octet-stream',
    sh: 'application/x-sh',
    // office documents
    pdf: 'application/pdf',
    doc: 'application/msword',
    docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    xls: 'application/vnd.ms-excel',
    xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ppt: 'application/vnd.ms-powerpoint',
    pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    odt: 'application/vnd.oasis.opendocument.text',
    ods: 'application/vnd.oasis.opendocument.spreadsheet',
    odp: 'application/vnd.oasis.opendocument.presentation',
    // images/doc misc
    pdfa: 'application/pdf',
    // code / wasm
    wasm: 'application/wasm',
    // torrents / misc
    torrent: 'application/x-bittorrent',
    // plist / mac
    plist: 'application/xml',
    // signature
    sig: 'application/pgp-signature',
    asc: 'text/plain'
  };
  return extToMime[ext] || 'application/octet-stream';
}