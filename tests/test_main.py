import csv
import json
import logging
import os
import tempfile
import unittest

import main


def _silent_logger():
    """Return a logger that discards output, for use in tests."""
    log = logging.getLogger('test_main')
    log.handlers = [logging.NullHandler()]
    log.setLevel(logging.CRITICAL)
    return log


class FakeIntelX:
    """Minimal stand-in for the IntelX SDK client."""

    def __init__(self, contents_by_id=None, fail_times=0):
        self.contents_by_id = contents_by_id or {}
        self.fail_times = fail_times
        self.calls = 0

    def FILE_VIEW(self, _type, _media, storageid, _bucket):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise OSError('transient network error')
        return self.contents_by_id.get(storageid, '')

    def search(self, term, maxresults, buckets, datefrom, dateto):  # noqa: D401
        return {'records': []}


def _make_leak(storageid, name='leak', date=None):
    leak = {
        'storageid': storageid,
        'type': 0,
        'media': 0,
        'bucket': 'leaks.public',
        'name': name,
    }
    if date is not None:
        leak['date'] = date
    return leak


class ResolveOutputPathTests(unittest.TestCase):
    def test_default_path_from_target(self):
        args = main.parse_args(['-t', 'example.com', '-f', 'json'])
        self.assertEqual(main.resolve_output_path(args), 'out/example.com-creds.json')

    def test_explicit_output_goes_into_out_dir(self):
        args = main.parse_args(['-t', 'example.com', '-o', 'creds.txt'])
        self.assertEqual(main.resolve_output_path(args), 'out/creds.txt')


class ResolveSafeOutputPathTests(unittest.TestCase):
    def test_default_derives_from_main_output(self):
        self.assertEqual(
            main.resolve_safe_output_path('out/example.com-creds.csv', None),
            os.path.join('out', 'example.com-creds-safe.csv'),
        )

    def test_absolute_arg_is_kept(self):
        self.assertEqual(main.resolve_safe_output_path('out/x.csv', '/tmp/share.csv'), '/tmp/share.csv')

    def test_out_prefixed_arg_is_kept(self):
        self.assertEqual(main.resolve_safe_output_path('out/x.csv', 'out/share.csv'), 'out/share.csv')

    def test_bare_arg_is_placed_in_out(self):
        self.assertEqual(main.resolve_safe_output_path('out/x.csv', 'share.csv'), 'out/share.csv')


class ParseArgsTests(unittest.TestCase):
    def test_safe_output_implies_safe_share(self):
        args = main.parse_args(['-t', 'example.com', '--safe-output', 'share.csv'])
        self.assertTrue(args.safe_share)

    def test_workers_must_be_positive(self):
        with self.assertRaises(SystemExit):
            main.parse_args(['-t', 'example.com', '--workers', '0'])

    def test_negative_delay_rejected(self):
        with self.assertRaises(SystemExit):
            main.parse_args(['-t', 'example.com', '--delay', '-1'])

    def test_defaults(self):
        args = main.parse_args(['-t', 'example.com'])
        self.assertEqual(args.workers, 1)
        self.assertEqual(args.delay, main.REQUEST_DELAY)
        self.assertEqual(args.format, 'txt')


class LoadExistingDedupTests(unittest.TestCase):
    def setUp(self):
        self.log = _silent_logger()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _path(self, name):
        return os.path.join(self.tmp.name, name)

    def test_missing_file_returns_empty(self):
        self.assertEqual(main.load_existing_dedup(self._path('nope.json'), 'json', self.log), set())

    def test_json_loads_keys(self):
        path = self._path('creds.json')
        with open(path, 'w') as f:
            json.dump([{'identity': 'Admin', 'password': 'Pass123'}], f)
        seen = main.load_existing_dedup(path, 'json', self.log)
        self.assertIn('admin:Pass123', seen)

    def test_csv_loads_keys(self):
        path = self._path('creds.csv')
        with open(path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['identity', 'password'])
            writer.writeheader()
            writer.writerow({'identity': 'User', 'password': 'Secret1'})
        seen = main.load_existing_dedup(path, 'csv', self.log)
        self.assertIn('user:Secret1', seen)

    def test_corrupt_json_is_non_fatal(self):
        path = self._path('creds.json')
        with open(path, 'w') as f:
            f.write('{not valid json')
        # Should not raise; returns whatever loaded (empty).
        self.assertEqual(main.load_existing_dedup(path, 'json', self.log), set())


class WriteJsonOutputTests(unittest.TestCase):
    def setUp(self):
        self.log = _silent_logger()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _path(self, name='out.json'):
        return os.path.join(self.tmp.name, name)

    def test_writes_and_merges(self):
        path = self._path()
        main.write_json_output([{'identity': 'a', 'password': 'p1'}], path, self.log)
        main.write_json_output([{'identity': 'b', 'password': 'p2'}], path, self.log)
        with open(path) as f:
            data = json.load(f)
        self.assertEqual(len(data), 2)
        self.assertEqual({e['identity'] for e in data}, {'a', 'b'})

    def test_corrupt_existing_is_backed_up_not_lost(self):
        path = self._path()
        with open(path, 'w') as f:
            f.write('garbage{')
        main.write_json_output([{'identity': 'a', 'password': 'p1'}], path, self.log)
        self.assertTrue(os.path.exists(path + '.corrupt'))
        with open(path) as f:
            data = json.load(f)
        self.assertEqual(len(data), 1)

    def test_no_temp_file_left_behind(self):
        path = self._path()
        main.write_json_output([{'identity': 'a', 'password': 'p1'}], path, self.log)
        leftovers = [n for n in os.listdir(self.tmp.name) if '.tmp.' in n]
        self.assertEqual(leftovers, [])


class WriteCsvOutputTests(unittest.TestCase):
    def setUp(self):
        self.log = _silent_logger()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _path(self, name='out.csv'):
        return os.path.join(self.tmp.name, name)

    def _read_rows(self, path):
        with open(path) as f:
            return list(csv.DictReader(f))

    def test_writes_header_and_rows(self):
        path = self._path()
        written = main.write_csv_output(
            [{'identity': 'a', 'password': 'p1', 'url': 'x.com'}], path, self.log
        )
        self.assertEqual(written, 1)
        rows = self._read_rows(path)
        self.assertEqual(rows[0]['identity'], 'a')

    def test_dedup_on_disk_even_when_seen_set_empty(self):
        path = self._path()
        cred = {'identity': 'a', 'password': 'p1', 'url': 'x.com'}
        # First run writes the row.
        main.write_csv_output([cred], path, self.log)
        # Second run with a fresh (empty) in-memory set must NOT append a duplicate,
        # because dedup happens against the file content too.
        written = main.write_csv_output([dict(cred)], path, self.log)
        self.assertEqual(written, 0)
        self.assertEqual(len(self._read_rows(path)), 1)


class WriteTxtOutputTests(unittest.TestCase):
    def setUp(self):
        self.log = _silent_logger()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_appends_canonical_with_date_prefix(self):
        path = os.path.join(self.tmp.name, 'out.txt')
        main.write_txt_output([{'canonical': 'x.com:a:p1', 'date': '2024-05-01'}], path, self.log)
        main.write_txt_output([{'canonical': 'y.com:b:p2'}], path, self.log)  # missing date
        with open(path) as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        self.assertEqual(lines, ['2024-05-01 | x.com:a:p1', 'unknown | y.com:b:p2'])

    def test_txt_line_still_round_trips_through_extractor(self):
        # The date prefix must not stop the credential being re-parsed (resume/safe-share).
        from custom.credential_extractor import extract_credentials_from_line
        line = '2024-05-01 | www.gamelife.it:alice@example.com:Str0ngPass9'
        cands = extract_credentials_from_line(line, mode='aggressive')
        self.assertTrue(any(c['identity'] == 'alice@example.com' and c['password'] == 'Str0ngPass9'
                            for c in cands))


class LeakDateTests(unittest.TestCase):
    def test_prefers_date_then_added_then_unknown(self):
        self.assertEqual(main._leak_date({'date': '2024-05-01 00:00:00'}), '2024-05-01')
        self.assertEqual(main._leak_date({'date': '2024-05-01T12:30:00'}), '2024-05-01')
        self.assertEqual(main._leak_date({'added': '2023-01-02T00:00:00'}), '2023-01-02')
        self.assertEqual(main._leak_date({}), 'unknown')
        self.assertEqual(main._leak_date({'date': ''}), 'unknown')


class FileViewRetryTests(unittest.TestCase):
    def setUp(self):
        self.log = _silent_logger()

    def test_retries_then_succeeds(self):
        ix = FakeIntelX(contents_by_id={'s1': 'ok'}, fail_times=2)
        retry = main.RetryConfig(max_retries=3, retry_delay=0)
        result = main.file_view_with_retry(ix, _make_leak('s1'), self.log, retry)
        self.assertEqual(result, 'ok')
        self.assertEqual(ix.calls, 3)

    def test_raises_after_exhausting_retries(self):
        ix = FakeIntelX(contents_by_id={'s1': 'ok'}, fail_times=5)
        retry = main.RetryConfig(max_retries=2, retry_delay=0)
        with self.assertRaises(OSError):
            main.file_view_with_retry(ix, _make_leak('s1'), self.log, retry)


class RunSearchTests(unittest.TestCase):
    def setUp(self):
        self.log = _silent_logger()

    def test_dedups_by_storageid(self):
        class SearchIX:
            def search(self, term, maxresults, buckets, datefrom, dateto):
                return {'records': [{'storageid': 'dup'}, {'storageid': 'dup'}]}

        results = main.run_search(SearchIX(), ['t'], ['b'], 'a', 'b', 10, self.log)
        self.assertEqual(len(results), 1)

    def test_handles_nonetype_records_typeerror(self):
        class NullIX:
            def search(self, term, maxresults, buckets, datefrom, dateto):
                raise TypeError("'NoneType' object is not iterable")

        results = main.run_search(NullIX(), ['t'], ['b'], 'a', 'b', 10, self.log)
        self.assertEqual(results, [])


class ResolveBucketsTests(unittest.TestCase):
    def setUp(self):
        self.log = _silent_logger()

    def test_uses_licensed_buckets_when_available(self):
        class CapsIX:
            def GET_CAPABILITIES(self):
                return {'buckets': ['leaks.private', 'leaks.logs', 'pastes']}

        buckets = main.resolve_buckets(CapsIX(), self.log)
        self.assertEqual(tuple(buckets), ('leaks.private', 'leaks.logs', 'pastes'))

    def test_parses_bucket_objects(self):
        class CapsIX:
            def GET_CAPABILITIES(self):
                return {'buckets': [{'bucket': 'leaks.private'}, {'name': 'leaks.logs'}]}

        self.assertEqual(tuple(main.resolve_buckets(CapsIX(), self.log)),
                         ('leaks.private', 'leaks.logs'))

    def test_falls_back_on_error(self):
        class BoomIX:
            def GET_CAPABILITIES(self):
                raise RuntimeError('network down')

        self.assertEqual(tuple(main.resolve_buckets(BoomIX(), self.log)), main.BUCKETS)

    def test_falls_back_when_no_buckets_in_payload(self):
        class EmptyIX:
            def GET_CAPABILITIES(self):
                return {'status': 0, 'paths': {}}

        self.assertEqual(tuple(main.resolve_buckets(EmptyIX(), self.log)), main.BUCKETS)


class ComputeDateRangeTests(unittest.TestCase):
    def test_dateto_covers_whole_final_day(self):
        date_from, date_to = main.compute_date_range(6)
        self.assertTrue(date_from.endswith('00:00:00'))
        self.assertTrue(date_to.endswith('23:59:59'))


class ProcessLeaksTests(unittest.TestCase):
    def setUp(self):
        self.log = _silent_logger()
        self.target = 'example.com'
        self.target_context = main.build_target_context(self.target)

    def _run(self, leaks, contents, workers=1):
        ix = FakeIntelX(contents_by_id=contents)
        seen = set()
        return main.process_leaks(
            ix,
            leaks,
            mode='balanced',
            target=self.target,
            target_context=self.target_context,
            person_context=None,
            seen=seen,
            log=self.log,
            workers=workers,
            delay=0,
        )

    def test_extracts_and_dedups_across_leaks(self):
        contents = {
            's1': 'example.com:admin:StrongPass1',
            's2': 'example.com:admin:StrongPass1',  # duplicate
        }
        leaks = [_make_leak('s1'), _make_leak('s2')]
        new_creds, stats = self._run(leaks, contents)
        self.assertEqual(len(new_creds), 1)
        self.assertEqual(stats['new_credentials'], 1)
        self.assertEqual(stats['duplicates'], 1)

    def test_credential_carries_leak_date(self):
        contents = {'s1': 'example.com:admin:StrongPass1'}
        leaks = [_make_leak('s1', date='2024-05-01T00:00:00')]
        new_creds, _ = self._run(leaks, contents)
        self.assertEqual(len(new_creds), 1)
        self.assertEqual(new_creds[0]['date'], '2024-05-01')

    def test_concurrent_matches_sequential_result_set(self):
        contents = {
            's1': 'example.com:admin:StrongPass1',
            's2': 'example.com:user2:AnotherPw2',
            's3': 'example.com:user3:ThirdPw33',
        }
        leaks = [_make_leak(f's{i}') for i in (1, 2, 3)]
        seq_creds, _ = self._run(leaks, contents, workers=1)
        par_creds, _ = self._run(leaks, contents, workers=4)
        self.assertEqual(
            {c['canonical'] for c in seq_creds},
            {c['canonical'] for c in par_creds},
        )
        self.assertEqual(len(par_creds), 3)

    def test_failed_file_view_does_not_abort_run(self):
        ix = FakeIntelX(contents_by_id={'s2': 'example.com:admin:StrongPass1'}, fail_times=99)
        # s1 always fails; ensure s1's failure is isolated and s2 isn't reached
        # via the same client (fail_times affects all calls), so just assert no raise.
        seen = set()
        new_creds, _ = main.process_leaks(
            ix,
            [_make_leak('s1')],
            mode='balanced',
            target=self.target,
            target_context=self.target_context,
            person_context=None,
            seen=seen,
            log=self.log,
            workers=1,
            delay=0,
            retry=main.RetryConfig(max_retries=1, retry_delay=0),
        )
        self.assertEqual(new_creds, [])


class WriteSafeShareTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_json_source_produces_anonymized_csv(self):
        src = os.path.join(self.tmp.name, 'creds.json')
        with open(src, 'w') as f:
            json.dump(
                [
                    {'url': 'x.com', 'identity': 'admin', 'password': 'Secret123', 'source': 'leakA'},
                    {'url': 'x.com', 'identity': 'admin', 'password': 'Secret123', 'source': 'leakA'},
                ],
                f,
            )
        dest = os.path.join(self.tmp.name, 'safe.csv')
        count = main.write_safe_share_file(src, 'json', dest)
        self.assertEqual(count, 1)  # deduped
        with open(dest) as f:
            rows = list(csv.DictReader(f, delimiter=';'))
        self.assertEqual(rows[0]['User'], 'admin')
        self.assertNotEqual(rows[0]['Password'], 'Secret123')  # anonymized
        self.assertTrue(rows[0]['Password'].startswith('S'))

    def test_safe_share_carries_date_column(self):
        src = os.path.join(self.tmp.name, 'creds.json')
        with open(src, 'w') as f:
            json.dump([{'url': 'x.com', 'identity': 'admin', 'password': 'Secret123',
                        'source': 'leakA', 'date': '2024-05-01'}], f)
        dest = os.path.join(self.tmp.name, 'safe.csv')
        main.write_safe_share_file(src, 'json', dest)
        with open(dest) as f:
            rows = list(csv.DictReader(f, delimiter=';'))
        self.assertEqual(rows[0]['Date'], '2024-05-01')


class CsvDateColumnTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = _silent_logger()

    def test_csv_output_has_date_column(self):
        path = os.path.join(self.tmp.name, 'out.csv')
        main.write_csv_output(
            [{'identity': 'a@x.com', 'password': 'p1', 'url': 'x.com', 'date': '2024-05-01'}],
            path, self.log,
        )
        with open(path) as f:
            rows = list(csv.DictReader(f))
        self.assertIn('date', rows[0])
        self.assertEqual(rows[0]['date'], '2024-05-01')


if __name__ == '__main__':
    unittest.main()
