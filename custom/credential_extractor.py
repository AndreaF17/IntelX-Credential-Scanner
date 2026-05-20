#!/usr/bin/env python3
import re
from urllib.parse import urlparse

DEFAULT_MODE = 'balanced'
EXTRACTION_MODES = {
    'strict': {
        'min_confidence': 0.82,
        'allow_kv': True,
        'enable_window_triplets': False,
        'allow_identity_without_url': False,
    },
    'balanced': {
        'min_confidence': 0.66,
        'allow_kv': True,
        'enable_window_triplets': True,
        'allow_identity_without_url': True,
    },
    'aggressive': {
        'min_confidence': 0.48,
        'allow_kv': True,
        'enable_window_triplets': True,
        'allow_identity_without_url': True,
    },
}

EMAIL_INLINE_PATTERN = re.compile(r'([^/:\s;|,]+@[^/:\s;|,]+\.[a-zA-Z]{2,}):([^\s;|,]+)')
URL_INLINE_PATTERN = re.compile(r'((?:https?://)[^\s:;|,]+):([^:@/\s;|,]+):([^\s;|,]+)')
HOST_INLINE_PATTERN = re.compile(r'((?=[^:\s;|,]*[./])[^:\s;|,]+):([^:@/\s;|,]+):([^\s;|,]+)')
DELIMITER_PATTERN = re.compile(r'\s*[;|,\t]\s*')
KV_PAIR_PATTERN = re.compile(
    r'(?P<key>url|site|host|domain|user|username|login|email|pass|password|pwd)\s*[:=]\s*'
    r'(?P<value>"[^"]*"|\'[^\']*\'|.*?)(?=(?:\s+(?:url|site|host|domain|user|username|login|email|pass|password|pwd)\s*[:=])|$)',
    re.IGNORECASE,
)


def sanitize_value(value):
    value = value.strip().strip('"\'').strip()
    return value.rstrip(';|,')


def normalize_obfuscations(value):
    lowered = value
    lowered = re.sub(r'hxxps://', 'https://', lowered, flags=re.IGNORECASE)
    lowered = re.sub(r'hxxp://', 'http://', lowered, flags=re.IGNORECASE)
    lowered = lowered.replace('[.]', '.').replace('(.)', '.').replace('{.}', '.')
    lowered = lowered.replace('\\.', '.')
    lowered = re.sub(r'\s+dot\s+', '.', lowered, flags=re.IGNORECASE)
    return lowered


def decode_punycode_host(host):
    labels = []
    for label in host.split('.'):
        if not label:
            continue
        try:
            labels.append(label.encode('ascii').decode('idna'))
        except UnicodeError:
            labels.append(label)
    return '.'.join(labels)


def canonicalize_url_part(url_part):
    url_part = sanitize_value(normalize_obfuscations(url_part))
    if not url_part:
        return ''

    parsed = urlparse(url_part if '://' in url_part else f'http://{url_part}')
    host = parsed.hostname
    if host:
        decoded_host = decode_punycode_host(host)
        path = parsed.path or ''
        if path == '/':
            path = ''
        if '://' in url_part:
            scheme = parsed.scheme or 'http'
            return f"{scheme}://{decoded_host}{path}"
        return f"{decoded_host}{path}"
    return url_part


def normalize_for_matching(value):
    value = normalize_obfuscations(value)
    value = value.lower()
    return re.sub(r'[^a-z0-9]', '', value)


def build_target_context(target):
    target_plain = target.lstrip('@').strip().lower()
    variants = {target_plain, normalize_obfuscations(target_plain).lower()}

    parsed = urlparse(target_plain if '://' in target_plain else f'http://{target_plain}')
    if parsed.hostname:
        variants.add(parsed.hostname.lower())
        variants.add(decode_punycode_host(parsed.hostname.lower()))

    normalized_variants = {normalize_for_matching(item) for item in variants if item}
    normalized_variants = {item for item in normalized_variants if item}
    return {
        'target_plain': target_plain,
        'variants': {item for item in variants if item},
        'normalized_variants': normalized_variants,
    }


def looks_like_url_part(value):
    value = sanitize_value(value)
    return bool(value) and ('.' in value or '/' in value)


def looks_like_identity(value):
    value = sanitize_value(value)
    return bool(value) and ':' not in value and '\n' not in value


def looks_like_password(value, mode):
    value = sanitize_value(value)
    if not value:
        return False

    min_length = 3
    if mode == 'strict':
        min_length = 5
    return len(value) >= min_length


def calculate_confidence(identity, password, url_part, pattern):
    base = {
        'url_delimited': 0.94,
        'host_delimited': 0.88,
        'email_delimited': 0.86,
        'kv_pairs': 0.78,
        'window_triplet': 0.62,
    }.get(pattern, 0.55)

    if '@' in identity:
        base += 0.05
    if looks_like_url_part(url_part):
        base += 0.04
    if len(password) >= 8:
        base += 0.04
    if re.search(r'\d', password) and re.search(r'[A-Za-z]', password):
        base += 0.03

    base = min(base, 0.99)
    return round(base, 3)


def candidate_mentions_target(candidate, raw_line, target_context):
    texts = [
        raw_line,
        candidate.get('url', ''),
        candidate.get('identity', ''),
        candidate.get('canonical', ''),
    ]

    for text in texts:
        if not text:
            continue
        lowered = normalize_obfuscations(text).lower()
        normalized = normalize_for_matching(text)

        for variant in target_context['variants']:
            if variant and variant in lowered:
                return True
        for normalized_variant in target_context['normalized_variants']:
            if normalized_variant and normalized_variant in normalized:
                return True
    return False


def _mode_config(mode):
    return EXTRACTION_MODES.get(mode, EXTRACTION_MODES[DEFAULT_MODE])


def _build_candidate(candidates, seen, identity, password, url_part, pattern, raw_line):
    identity = sanitize_value(identity)
    password = sanitize_value(password)
    url_part = canonicalize_url_part(url_part)

    if not identity or not password:
        return

    dedup_key = f"{identity.lower()}:{password}"
    canonical = f"{url_part}:{identity}:{password}" if url_part else f"{identity}:{password}"

    if dedup_key in seen:
        return

    confidence = calculate_confidence(identity, password, url_part, pattern)
    seen.add(dedup_key)
    candidates.append({
        'identity': identity,
        'password': password,
        'url': url_part,
        'pattern': pattern,
        'confidence': confidence,
        'canonical': canonical,
        'dedup_key': dedup_key,
        'raw_line': raw_line,
    })


def _extract_from_kv_pairs(chunk, candidates, seen, mode):
    if not _mode_config(mode)['allow_kv']:
        return

    pairs = list(KV_PAIR_PATTERN.finditer(chunk))
    if not pairs:
        return

    current = {'url': '', 'identity': '', 'password': ''}
    for pair in pairs:
        key = pair.group('key').lower()
        value = sanitize_value(pair.group('value'))

        if key in {'url', 'site', 'host', 'domain'}:
            if current['identity'] and current['password']:
                _build_candidate(
                    candidates,
                    seen,
                    current['identity'],
                    current['password'],
                    current['url'],
                    'kv_pairs',
                    chunk,
                )
                current = {'url': '', 'identity': '', 'password': ''}
            current['url'] = value
        elif key in {'user', 'username', 'login', 'email'}:
            current['identity'] = value
        elif key in {'pass', 'password', 'pwd'}:
            current['password'] = value

        if current['identity'] and current['password']:
            _build_candidate(
                candidates,
                seen,
                current['identity'],
                current['password'],
                current['url'],
                'kv_pairs',
                chunk,
            )
            current = {'url': current['url'], 'identity': '', 'password': ''}


def _extract_from_triplet_windows(chunk, candidates, seen, mode):
    if not _mode_config(mode)['enable_window_triplets']:
        return

    normalized_chunk = DELIMITER_PATTERN.sub(':', chunk)
    tokens = [token.strip() for token in normalized_chunk.split(':') if token.strip()]
    for index in range(len(tokens) - 2):
        url_part, identity, password = tokens[index:index + 3]
        if not looks_like_url_part(url_part):
            continue
        if not looks_like_identity(identity):
            continue
        if not looks_like_password(password, mode):
            continue

        _build_candidate(candidates, seen, identity, password, url_part, 'window_triplet', chunk)


def _extract_from_inline_patterns(chunk, candidates, seen):
    for match in URL_INLINE_PATTERN.finditer(chunk):
        _build_candidate(candidates, seen, match.group(2), match.group(3), match.group(1), 'url_delimited', chunk)

    for match in HOST_INLINE_PATTERN.finditer(chunk):
        _build_candidate(candidates, seen, match.group(2), match.group(3), match.group(1), 'host_delimited', chunk)

    for match in EMAIL_INLINE_PATTERN.finditer(chunk):
        prefix = chunk[:match.start()].rstrip(':').strip()
        _build_candidate(candidates, seen, match.group(1), match.group(2), prefix, 'email_delimited', chunk)


def _split_chunks(line):
    chunks = [line]
    for splitter in [r'\s*\|\|\s*', r'\s+\|\s+', r'\s*&&\s*', r'\s{2,}']:
        expanded = []
        for chunk in chunks:
            expanded.extend(re.split(splitter, chunk))
        chunks = expanded

    unique = []
    seen = set()
    for chunk in chunks:
        chunk = chunk.strip()
        if chunk and chunk not in seen:
            seen.add(chunk)
            unique.append(chunk)
    return unique


def extract_credentials_from_line(line, mode=DEFAULT_MODE):
    raw_line = line.strip()
    if not raw_line:
        return []

    normalized_line = normalize_obfuscations(raw_line)
    candidates = []
    seen = set()

    chunks = _split_chunks(normalized_line)
    if raw_line not in chunks:
        chunks.append(raw_line)

    for chunk in chunks:
        _extract_from_inline_patterns(chunk, candidates, seen)
        _extract_from_kv_pairs(chunk, candidates, seen, mode)
        _extract_from_triplet_windows(chunk, candidates, seen, mode)

    mode_config = _mode_config(mode)
    if not mode_config['allow_identity_without_url']:
        candidates = [candidate for candidate in candidates if candidate.get('url')]

    return sorted(candidates, key=lambda item: item['confidence'], reverse=True)


def parse_credential(line, mode=DEFAULT_MODE):
    candidates = extract_credentials_from_line(line, mode=mode)
    if not candidates:
        return None

    best = candidates[0]
    return best['identity'], best['password'], best['url']
