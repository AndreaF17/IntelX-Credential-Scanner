#!/usr/bin/env python3
from datetime import datetime
from dateutil.relativedelta import relativedelta
import re
import argparse
import logging
import colorlog
from dotenv import load_dotenv
import os
import sys
import time
import json
import csv
import importlib

from custom.credential_extractor import (
    DEFAULT_MODE,
    EXTRACTION_MODES,
    build_person_email_context,
    build_search_terms,
    build_target_context,
    candidate_mentions_person_email,
    candidate_mentions_target,
    extract_credentials_from_line,
    is_email_target,
)
from custom.parser import anonymize_password, parse_line_candidates


def load_intelx_client():
    """Load IntelX client constructor from available SDK package names."""
    for module_name in ('intelxapi', 'intelx'):
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue

        client = getattr(module, 'intelx', None)
        if client is not None:
            return client
    return None


INTELX_CLIENT = load_intelx_client()

# Maximum retries for FILE_VIEW API calls
MAX_RETRIES = 3
RETRY_DELAY = 2          # seconds, doubles after each retry
REQUEST_DELAY = 0.5       # seconds between FILE_VIEW calls


def resolve_safe_output_path(main_output_path, safe_output_arg):
    """Resolve the destination path for the safe-share CSV output."""
    if safe_output_arg:
        if os.path.isabs(safe_output_arg) or safe_output_arg.startswith('out/'):
            return safe_output_arg
        return f"out/{safe_output_arg}"

    base_name = os.path.splitext(os.path.basename(main_output_path))[0]
    return os.path.join('out', f"{base_name}-safe.csv")


def iter_credentials_for_safe_share(main_output_path, output_format):
    """Yield normalized credential dicts from the main output file."""
    if output_format == 'json':
        with open(main_output_path, 'r') as f:
            entries = json.load(f)

        if isinstance(entries, list):
            for entry in entries:
                yield {
                    'url': entry.get('url', ''),
                    'identity': entry.get('identity') or entry.get('email', ''),
                    'password': entry.get('password', ''),
                    'source': entry.get('source', ''),
                }

    elif output_format == 'csv':
        with open(main_output_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                yield {
                    'url': row.get('url', ''),
                    'identity': row.get('identity') or row.get('email', ''),
                    'password': row.get('password', ''),
                    'source': row.get('source', ''),
                }

    else:  # txt
        with open(main_output_path, 'r') as f:
            for line in f:
                for target, user, password in parse_line_candidates(line):
                    yield {
                        'url': target,
                        'identity': user,
                        'password': password,
                        'source': '',
                    }


def write_safe_share_file(main_output_path, output_format, safe_output_path):
    """Create a sanitized CSV suitable for external sharing."""
    safe_rows = []
    seen = set()

    for cred in iter_credentials_for_safe_share(main_output_path, output_format):
        identity = (cred.get('identity') or '').strip()
        password = (cred.get('password') or '').strip()
        if not identity or not password:
            continue

        dedup_key = f"{identity.lower()}:{password}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        safe_rows.append({
            'TARGET': cred.get('url', ''),
            'User': identity,
            'Password': anonymize_password(password),
            'Source': cred.get('source', ''),
        })

    if not safe_rows:
        return 0

    safe_dir = os.path.dirname(safe_output_path)
    if safe_dir:
        os.makedirs(safe_dir, exist_ok=True)

    with open(safe_output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['TARGET', 'User', 'Password', 'Source'], delimiter=';')
        writer.writeheader()
        writer.writerows(safe_rows)

    return len(safe_rows)


# ── Argument parser ─────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description='Search for leaked credentials')
parser.add_argument('-t', '--target', type=str, help='Target to search (domain or email)', required=True)
parser.add_argument('-m', '--maxresults', type=int, help='Maximum number of results to return', default=100)
parser.add_argument('-k', '--apikey', type=str, help='IntelX API key', required=False)
parser.add_argument('-o', '--output', type=str, help='Output file to save the results', default=None)
parser.add_argument('-f', '--format', type=str, choices=['txt', 'json', 'csv'], help='Output format (txt, json, csv)', default='txt')
parser.add_argument('-r', '--range', type=int, help='Search range in months', default=6)
parser.add_argument('-d', '--debug', action='store_true', help='Enable DEBUG logging (default: INFO)')
parser.add_argument('-e', '--email', action='store_true', help='Also search for @domain pattern')
parser.add_argument(
    '--person-name',
    type=str,
    default=None,
    help='Optional full name to enrich person-email search terms',
)
parser.add_argument(
    '--safe-share',
    action='store_true',
    help='Generate a sanitized CSV file safe to share with external clients',
)
parser.add_argument(
    '--safe-output',
    type=str,
    default=None,
    help='Optional safe-share output filename (default: out/<output>-safe.csv)',
)
parser.add_argument(
    '--mode',
    type=str,
    choices=sorted(EXTRACTION_MODES.keys()),
    default=DEFAULT_MODE,
    help='Extraction mode: strict (precision), balanced (default), aggressive (recall)',
)

args = parser.parse_args()

if args.safe_output and not args.safe_share:
    args.safe_share = True

# Set default output filename based on target if not provided
if not args.output:
    args.output = f"out/{args.target}-creds.{args.format}"
else:
    # If user provided output, also put it in out/ directory
    args.output = f"out/{args.output}"

# Configure colored logging
log_level = logging.DEBUG if args.debug else logging.INFO
logger = colorlog.getLogger(__name__)
logger.setLevel(log_level)

handler = colorlog.StreamHandler()
handler.setLevel(log_level)
formatter = colorlog.ColoredFormatter(
    '[%(log_color)s%(levelname)s%(reset)s] %(message)s',
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white',
    }
)
handler.setFormatter(formatter)
logger.addHandler(handler)
log = logger


# ── API key ──────────────────────────────────────────────────────────────────
try:
    if not args.apikey:
        load_dotenv()
        args.apikey = os.getenv('INTELX_API_KEY')
        log.debug(f"Using API key from environment variable: {args.apikey}")
    if not args.apikey:
        log.error("API key is required. Please provide it using -k or set INTELX_API_KEY in your environment variables.")
        sys.exit(1)
except Exception as e:
    log.error(f"Error loading API key: {e}")
    sys.exit(1)


# ── Date range ───────────────────────────────────────────────────────────────
today = datetime.today()
six_months_ago = today - relativedelta(months=args.range)
today_formatted = today.strftime("%Y-%m-%d") + " 00:00:00"
six_months_ago_formatted = six_months_ago.strftime("%Y-%m-%d") + " 00:00:00"

log.info(f"Searching from {six_months_ago_formatted} to {today_formatted}")


# ── IntelX search ────────────────────────────────────────────────────────────
target = args.target
target_is_email = is_email_target(target)
target_context = build_target_context(target)
person_context = build_person_email_context(target, person_name=args.person_name) if target_is_email else None

if args.person_name and not target_is_email:
    log.warning("--person-name is most useful with an email target and will be ignored for domain targets")

BUCKETS = ['leaks.private', 'leaks.public', 'leaks.private.li', 'pastes']

search_terms = build_search_terms(target, include_email_pattern=args.email, person_name=args.person_name)
if target_is_email:
    log.info(f"Person-email mode enabled. Generated {len(search_terms)} search terms for '{target}'.")
elif args.email:
    log.info("Email search enabled: added @domain pattern search term")

try:
    if INTELX_CLIENT is None:
        log.error("IntelX SDK not installed. Install dependencies with: pip install -r requirements.txt")
        sys.exit(1)

    ix = INTELX_CLIENT(args.apikey)
    log.debug(f"IntelX API initialized for target: {target}")

    all_results = []
    seen_ids = set()
    for term in search_terms:
        for bucket in BUCKETS:
            log.debug(f"Searching bucket '{bucket}' for '{term}'...")
            try:
                try:
                    response = ix.search(term,
                                         maxresults=args.maxresults,
                                         buckets=[bucket],
                                         datefrom=six_months_ago_formatted,
                                         dateto=today_formatted)
                except TypeError as e:
                    # intelxapi can raise this when API returns {'records': None}
                    if "'NoneType' object is not iterable" in str(e):
                        log.debug(
                            f"IntelX SDK returned null records for term '{term}' in bucket '{bucket}', "
                            "treating as empty result"
                        )
                        response = {'records': []}
                    else:
                        raise

                records = response.get('records') if isinstance(response, dict) else []
                if not records:
                    records = []
                # deduplicate across buckets/terms by storageid
                for r in records:
                    sid = r.get('storageid')
                    if sid and sid not in seen_ids:
                        seen_ids.add(sid)
                        all_results.append(r)
                log.debug(f"  -> {len(records)} records from {bucket} for '{term}'")
            except Exception as e:
                log.warning(f"Bucket '{bucket}' failed for '{term}': {e}")
                continue

    results = all_results
    log.info(f"Found {len(results)} unique results across all buckets")
except Exception as e:
    log.error(f"Error searching IntelX API: {e}")
    sys.exit(1)

output_file = args.output

# Create output directory if it doesn't exist
os.makedirs('out', exist_ok=True)


# ── Resume: load previously saved credentials ───────────────────────────────
seen = set()

if os.path.exists(output_file):
    log.info(f"Resuming: loading existing credentials from {output_file}")
    try:
        if args.format == 'json':
            with open(output_file, 'r') as f:
                existing = json.load(f)
            for entry in existing:
                identity = entry.get('identity') or entry.get('email', '')
                password = entry.get('password', '')
                if identity and password:
                    seen.add(f"{identity.lower()}:{password}")
        elif args.format == 'csv':
            with open(output_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    identity = row.get('identity') or row.get('email', '')
                    password = row.get('password', '')
                    if identity and password:
                        seen.add(f"{identity.lower()}:{password}")
        else:  # txt
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        candidates = extract_credentials_from_line(line, mode='aggressive')
                        if candidates:
                            for candidate in candidates:
                                seen.add(candidate['dedup_key'])
                        else:
                            seen.add(line.lower())
        log.info(f"Loaded {len(seen)} existing credentials for dedup")
    except (json.JSONDecodeError, FileNotFoundError, StopIteration):
        log.warning(f"Could not parse existing output file, starting fresh dedup")
    except Exception as e:
        log.warning(f"Error loading existing output: {e}")


# ── Helper: FILE_VIEW with retries ──────────────────────────────────────────
def file_view_with_retry(ix, leak, max_retries=MAX_RETRIES):
    """Call FILE_VIEW with exponential backoff retry."""
    delay = RETRY_DELAY
    for attempt in range(1, max_retries + 1):
        try:
            return ix.FILE_VIEW(leak['type'], leak['media'],
                                leak['storageid'], leak['bucket'])
        except Exception as e:
            if attempt == max_retries:
                raise
            log.warning(f"FILE_VIEW attempt {attempt}/{max_retries} failed: {e}. Retrying in {delay}s...")
            time.sleep(delay)
            delay *= 2
    return ""


# ── Process leaks ───────────────────────────────────────────────────────────
new_creds = []   # list of dicts for json/csv output
extraction_stats = {
    'lines_scanned': 0,
    'candidates_extracted': 0,
    'pattern_skips': 0,
    'low_confidence_skips': 0,
    'target_skips': 0,
    'multi_candidate_lines': 0,
    'duplicates': 0,
    'new_credentials': 0,
}

try:
    for i, leak in enumerate(results):
        try:
            log.debug(f"Processing leak [{i+1}/{len(results)}]: {leak['name']}")
            contents = file_view_with_retry(ix, leak)

            for line in contents.split('\n'):
                line_stripped = line.strip()
                if not line_stripped:
                    continue

                extraction_stats['lines_scanned'] += 1

                candidates = extract_credentials_from_line(line_stripped, mode=args.mode)
                if not candidates:
                    extraction_stats['pattern_skips'] += 1
                    log.debug(f"Skipped (no valid credential pattern): {line_stripped}")
                    continue

                extraction_stats['candidates_extracted'] += len(candidates)
                accepted_for_line = 0

                for candidate in candidates:
                    if candidate['confidence'] < EXTRACTION_MODES[args.mode]['min_confidence']:
                        extraction_stats['low_confidence_skips'] += 1
                        log.debug(
                            f"Skipped (low confidence {candidate['confidence']:.2f}): {candidate['canonical']}"
                        )
                        continue

                    if person_context:
                        target_match = candidate_mentions_person_email(candidate, line_stripped, person_context)
                    else:
                        target_match = candidate_mentions_target(candidate, line_stripped, target_context)

                    if not target_match:
                        extraction_stats['target_skips'] += 1
                        log.debug(f"Skipped (target mismatch): {candidate['canonical']}")
                        continue

                    cred_key = candidate['dedup_key']

                    if cred_key in seen:
                        extraction_stats['duplicates'] += 1
                        log.debug(f"Duplicate skipped: {candidate['canonical']}")
                        continue

                    seen.add(cred_key)

                    identity = candidate['identity']
                    email_value = identity if '@' in identity else ''

                    new_creds.append({
                        'url': candidate['url'],
                        'identity': identity,
                        'email': email_value,
                        'password': candidate['password'],
                        'source': leak.get('name', 'unknown'),
                        'raw_line': line_stripped,
                        'raw': line_stripped,
                        'canonical': candidate['canonical'],
                        'confidence': candidate['confidence'],
                        'pattern': candidate['pattern'],
                    })
                    extraction_stats['new_credentials'] += 1
                    accepted_for_line += 1
                    log.info(
                        f"Found ({candidate['pattern']} {candidate['confidence']:.2f}): "
                        f"{candidate['canonical']}"
                    )

                if accepted_for_line > 1:
                    extraction_stats['multi_candidate_lines'] += 1

        except Exception as e:
            log.error(f"Error processing leak {leak.get('name', 'unknown')}: {e}")
            continue

        # rate limiting between FILE_VIEW calls
        if i < len(results) - 1:
            time.sleep(REQUEST_DELAY)

    # ── Write output ─────────────────────────────────────────────────────────
    if not new_creds:
        log.info("No new credentials found")
    else:
        if args.format == 'json':
            # merge with existing entries if resuming
            existing_entries = []
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        existing_entries = json.load(f)
                except (json.JSONDecodeError, FileNotFoundError):
                    pass
            all_entries = existing_entries + new_creds
            with open(output_file, 'w') as f:
                json.dump(all_entries, f, indent=2)

        elif args.format == 'csv':
            file_exists = os.path.exists(output_file) and os.path.getsize(output_file) > 0
            with open(output_file, 'a', newline='') as f:
                fieldnames = [
                    'url',
                    'identity',
                    'email',
                    'password',
                    'source',
                    'confidence',
                    'pattern',
                    'canonical',
                    'raw_line',
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                if not file_exists:
                    writer.writeheader()
                for cred in new_creds:
                    writer.writerow({key: cred.get(key, '') for key in fieldnames})

        else:  # txt
            with open(output_file, 'a') as f:
                for cred in new_creds:
                    f.write(f"{cred['canonical']}\n")

        log.info(f"Wrote {len(new_creds)} new credentials to: {output_file}")

    if args.safe_share:
        try:
            safe_output_file = resolve_safe_output_path(output_file, args.safe_output)
            if os.path.exists(output_file):
                safe_count = write_safe_share_file(output_file, args.format, safe_output_file)
            else:
                safe_count = 0

            if safe_count > 0:
                log.info(f"Wrote {safe_count} anonymized credentials to safe-share file: {safe_output_file}")
            else:
                log.info("Safe-share skipped: 0 anonymized credentials")
        except Exception as e:
            log.error(f"Failed to create safe-share output: {e}")

    log.info(f"Total unique credentials (all runs): {len(seen)}")
    log.info(
        "Extraction stats (%(mode)s) - scanned: %(lines_scanned)s, candidates: %(candidates_extracted)s, "
        "pattern_skips: %(pattern_skips)s, low_conf: %(low_confidence_skips)s, "
        "target_skips: %(target_skips)s, multi_lines: %(multi_candidate_lines)s, "
        "duplicates: %(duplicates)s, new: %(new_credentials)s",
        {
            **extraction_stats,
            'mode': args.mode,
        },
    )

except FileNotFoundError:
    log.error(f"Cannot create/write to output file: {output_file}")
    sys.exit(1)
except Exception as e:
    log.error(f"Error during credential search: {e}")
    sys.exit(1)
