#!/usr/bin/env python3
from intelxapi import intelx
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


# ── Credential validation regex ──────────────────────────────────────────────
# Matches  user@domain.tld:password  (password must be at least 1 char)
CRED_PATTERN = re.compile(r'([^/:\s]+@[^/:\s]+\.[a-zA-Z]{2,}):(.+)$')

# Maximum retries for FILE_VIEW API calls
MAX_RETRIES = 3
RETRY_DELAY = 2          # seconds, doubles after each retry
REQUEST_DELAY = 0.5       # seconds between FILE_VIEW calls


# ── Argument parser ─────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description='Search for leaked credentials')
parser.add_argument('-t', '--target', type=str, help='The target domain to search for', required=True)
parser.add_argument('-m', '--maxresults', type=int, help='Maximum number of results to return', default=100)
parser.add_argument('-k', '--apikey', type=str, help='IntelX API key', required=False)
parser.add_argument('-o', '--output', type=str, help='Output file to save the results', default=None)
parser.add_argument('-f', '--format', type=str, choices=['txt', 'json', 'csv'], help='Output format (txt, json, csv)', default='txt')
parser.add_argument('-r', '--range', type=int, help='Search range in months', default=6)
parser.add_argument('-d', '--debug', action='store_true', help='Enable DEBUG logging (default: INFO)')
parser.add_argument('-e', '--email', action='store_true', help='Also search for @domain pattern')

args = parser.parse_args()

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
escaped_target = re.escape(target)   # safe regex matching

BUCKETS = ['leaks.private', 'leaks.public', 'leaks.private.li', 'pastes']

search_terms = [target]
if args.email:
    email_target = f"@{target}" if not target.startswith("@") else target
    search_terms.append(email_target)
    log.info(f"Email search enabled: also searching for '{email_target}'")

try:
    ix = intelx(args.apikey)
    log.debug(f"IntelX API initialized for target: {target}")

    all_results = []
    seen_ids = set()
    for term in search_terms:
        for bucket in BUCKETS:
            log.debug(f"Searching bucket '{bucket}' for '{term}'...")
            try:
                records = ix.search(term,
                                    maxresults=args.maxresults,
                                    buckets=[bucket],
                                    datefrom=six_months_ago_formatted,
                                    dateto=today_formatted).get('records', [])
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
                cred_key = f"{entry.get('email', '')}:{entry.get('password', '')}"
                seen.add(cred_key)
        elif args.format == 'csv':
            with open(output_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cred_key = f"{row.get('email', '')}:{row.get('password', '')}"
                    seen.add(cred_key)
        else:  # txt
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        cred_match = CRED_PATTERN.search(line)
                        cred_key = cred_match.group(0) if cred_match else line
                        seen.add(cred_key)
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

try:
    for i, leak in enumerate(results):
        try:
            log.debug(f"Processing leak [{i+1}/{len(results)}]: {leak['name']}")
            contents = file_view_with_retry(ix, leak)

            for line in contents.split('\n'):
                # use escaped target for safe regex matching
                if not re.search(escaped_target, line, re.IGNORECASE):
                    continue

                line_stripped = line.strip()

                # password validation: only keep lines that look like user@domain:password
                cred_match = CRED_PATTERN.search(line_stripped)
                if not cred_match:
                    log.debug(f"Skipped (no valid credential pattern): {line_stripped}")
                    continue

                email = cred_match.group(1)
                password = cred_match.group(2)
                cred_key = f"{email}:{password}"

                if cred_key in seen:
                    log.debug(f"Duplicate skipped: {cred_key}")
                    continue

                seen.add(cred_key)

                # extract optional URL (everything before the email)
                url_part = line_stripped[:cred_match.start()].rstrip(':').strip()

                new_creds.append({
                    'url': url_part,
                    'email': email,
                    'password': password,
                    'source': leak.get('name', 'unknown'),
                    'raw': line_stripped,
                })
                log.info(f"Found: {line_stripped}")

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
                writer = csv.DictWriter(f, fieldnames=['url', 'email', 'password', 'source'])
                if not file_exists:
                    writer.writeheader()
                for cred in new_creds:
                    writer.writerow({k: cred[k] for k in ['url', 'email', 'password', 'source']})

        else:  # txt
            with open(output_file, 'a') as f:
                for cred in new_creds:
                    f.write(f"{cred['raw']}\n")

        log.info(f"Wrote {len(new_creds)} new credentials to: {output_file}")

    log.info(f"Total unique credentials (all runs): {len(seen)}")

except FileNotFoundError:
    log.error(f"Cannot create/write to output file: {output_file}")
    sys.exit(1)
except Exception as e:
    log.error(f"Error during credential search: {e}")
    sys.exit(1)
