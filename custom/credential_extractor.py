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
EMAIL_TARGET_PATTERN = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
NAME_TOKEN_SPLIT_PATTERN = re.compile(r'[^a-z0-9]+')


def _add_unique(target_list, seen, value):
    value = value.strip()
    if not value:
        return
    lowered = value.lower()
    if lowered in seen:
        return
    seen.add(lowered)
    target_list.append(value)


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

    parse_target = url_part if '://' in url_part else f'http://{url_part}'
    try:
        parsed = urlparse(parse_target)
        host = parsed.hostname
    except ValueError:
        # Broken URL fragments (commonly malformed IPv6 hosts) should not abort extraction.
        return url_part

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


def is_email_target(target):
    normalized = normalize_obfuscations(target.strip().lower())
    return bool(EMAIL_TARGET_PATTERN.match(normalized))


def _derive_person_name_variants(email, person_name=None, include_local_from_email=False):
    variants = []
    seen = set()

    email = normalize_obfuscations(email.strip().lower())
    local_part, _, _ = email.partition('@')
    local_tokens = [token for token in re.split(r'[._\-]+', local_part) if token]

    if include_local_from_email:
        if local_part:
            _add_unique(variants, seen, local_part)

        if len(local_tokens) >= 2:
            _add_unique(variants, seen, f"{local_tokens[0]} {local_tokens[-1]}")
            _add_unique(variants, seen, ''.join(local_tokens))

    if person_name:
        clean_name = ' '.join(person_name.strip().split())
        if clean_name:
            _add_unique(variants, seen, clean_name)
            _add_unique(variants, seen, f'"{clean_name}"')

            name_tokens = [
                token
                for token in NAME_TOKEN_SPLIT_PATTERN.split(clean_name.lower())
                if token
            ]
            if len(name_tokens) >= 2:
                _add_unique(variants, seen, ''.join(name_tokens))

    return variants


def build_search_terms(target, include_email_pattern=False, person_name=None):
    """Build IntelX search terms for domain/email/person targeting."""
    target_normalized = normalize_obfuscations(target.strip())
    terms = []
    seen = set()

    _add_unique(terms, seen, target_normalized)

    if is_email_target(target_normalized):
        email_value = target_normalized.lower()
        _, _, domain = email_value.partition('@')

        # Default behavior: exact email only.
        if person_name:
            for variant in _derive_person_name_variants(
                email_value,
                person_name=person_name,
                include_local_from_email=False,
            ):
                _add_unique(terms, seen, variant)

        if include_email_pattern and domain:
            _add_unique(terms, seen, f"@{domain}")

        return terms

    if include_email_pattern:
        email_target = f"@{target_normalized}" if not target_normalized.startswith('@') else target_normalized
        _add_unique(terms, seen, email_target)

    return terms


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


def build_person_email_context(email, person_name=None):
    """Build strict context for matching a specific person email target."""
    normalized_email = normalize_obfuscations(email.strip().lower())
    local_part, _, domain = normalized_email.partition('@')
    name_variants = _derive_person_name_variants(
        normalized_email,
        person_name=person_name,
        include_local_from_email=False,
    )

    return {
        'email': normalized_email,
        'email_normalized': normalize_for_matching(normalized_email),
        'local_part': local_part,
        'local_normalized': normalize_for_matching(local_part),
        'domain': domain,
        'domain_normalized': normalize_for_matching(domain),
        'name_variants': name_variants,
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


def candidate_mentions_person_email(candidate, raw_line, person_context):
    """Match candidate against a person email target without falling back to domain-only hits."""
    texts = [
        raw_line,
        candidate.get('identity', ''),
        candidate.get('url', ''),
        candidate.get('canonical', ''),
    ]

    local_norm = person_context.get('local_normalized', '')
    domain_norm = person_context.get('domain_normalized', '')
    email_norm = person_context.get('email_normalized', '')

    for text in texts:
        if not text:
            continue
        lowered = normalize_obfuscations(text).lower()
        normalized = normalize_for_matching(text)

        # Strong match on the exact email (supports obfuscated variants via normalization)
        if email_norm and email_norm in normalized:
            return True

        # Fallback: local + domain co-occurrence in the same line/candidate context
        if local_norm and domain_norm and local_norm in normalized and domain_norm in normalized:
            if '@' in lowered or 'email' in lowered or 'user' in lowered or 'login' in lowered:
                return True

        # If a person name was supplied, require name + domain proximity in same text
        for name_variant in person_context.get('name_variants', []):
            if name_variant and name_variant.lower() in lowered and domain_norm and domain_norm in normalized:
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
