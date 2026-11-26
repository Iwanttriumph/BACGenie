import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.toolbox import source as source_module
from src.toolbox.source import Source, load_input


class InputTests(unittest.TestCase):
    def test_legacy_nested_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'CVE-2024-10762.json'
            path.write_text(json.dumps({'vulnerability': {'id': 'CVE-2024-10762', 'description': 'nested'}}), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'Legacy nested input'):
                load_input(path)

    def test_flat_benchmark_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'repo').mkdir()
            (root / 'repo' / 'a.py').write_text('print(1)\n', encoding='utf-8')
            data = {
                'description': 'flat',
                'cwes': [{'id': 'CWE-863', 'value': 'CWE-863'}],
                'patch_commits': [{'content': 'patch'}],
                'sec_adv': [{'content': 'advisory'}],
                'sw_version': 'v1',
                'dir_tree': '.\n└── a.py',
                'repo_path': 'repo',
            }
            path = root / 'CVE-2024-10762.json'
            path.write_text(json.dumps(data), encoding='utf-8')
            raw, original, evidence, repository = load_input(path)
            self.assertEqual(original, data)
            self.assertEqual(evidence['vulnerability']['id'], 'CVE-2024-10762')
            self.assertEqual(evidence['vulnerability']['description'], 'flat')
            self.assertEqual(evidence['vulnerability']['patches'], data['patch_commits'])
            self.assertEqual(evidence['vulnerability']['advisories'], data['sec_adv'])
            self.assertEqual(evidence['vulnerability']['dir_tree'], data['dir_tree'])
            self.assertNotIn('patch_commits', evidence)
            self.assertNotIn('sec_adv', evidence)
            self.assertEqual(repository.root, (root / 'repo').resolve())
            self.assertEqual(repository.file_count, 1)

    def test_filename_id_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'CVE-2024-10762.json'
            path.write_text(json.dumps({'description': 'x', 'cve_id': 'CVE-2024-99999'}), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'conflicts'):
                load_input(path)

    def test_non_cve_filename_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.json'
            path.write_text(json.dumps({'description': 'x'}), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'CVE-xxxx-xxxx.json'):
                load_input(path)

    def test_missing_repo_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'CVE-2024-10762.json'
            path.write_text(json.dumps({'description': 'x', 'repo_path': 'missing'}), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'not a directory'):
                load_input(path)

    def test_relative_repo_does_not_fall_back(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'repo').mkdir()
            inputs = root / 'inputs'
            inputs.mkdir()
            path = inputs / 'CVE-2024-10762.json'
            path.write_text(json.dumps({'description': 'x', 'repo_path': 'repo'}), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'not a directory'):
                load_input(path)

    def test_absolute_repo_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / 'repo'
            repo.mkdir()
            path = root / 'CVE-2024-10762.json'
            path.write_text(json.dumps({'description': 'x', 'repo_path': str(repo)}), encoding='utf-8')
            _, _, _, repository = load_input(path)
            self.assertEqual(repository.root, repo.resolve())


class RetrievalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'a.py').write_text('\n'.join(f'line {i}' for i in range(1, 251)), encoding='utf-8')
        (self.root / 'dir').mkdir()
        (self.root / 'dir' / 'b.py').write_text('needle\n' * 120, encoding='utf-8')
        (self.root / 'dir' / 'c.txt').write_text('other\n', encoding='utf-8')
        (self.root / 'binary.bin').write_bytes(b'\0\1\2')
        self.source = Source(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_list_is_paginated_and_immediate(self):
        first = json.loads(self.source.execute({'op': 'list', 'path': ''})['result'])
        self.assertEqual(first['entries'], [
            {'path': 'a.py', 'type': 'file'},
            {'path': 'dir/', 'type': 'directory'},
        ])
        self.assertNotIn('binary.bin', [entry['path'] for entry in first['entries']])
        second = json.loads(self.source.execute({'op': 'list', 'path': 'dir/'})['result'])
        self.assertEqual([entry['path'] for entry in second['entries']], ['dir/b.py', 'dir/c.txt'])

    def test_list_offset_pagination(self):
        many = self.root / 'many'
        many.mkdir()
        for index in range(105):
            (many / f'f{index:03}.txt').write_text('x\n', encoding='utf-8')
        source = Source(self.root)
        first = json.loads(source.execute({'op': 'list', 'path': 'many/'})['result'])
        self.assertEqual(len(first['entries']), 100)
        self.assertEqual(first['next_offset'], 100)
        second = json.loads(source.execute({'op': 'list', 'path': 'many/', 'offset': 100})['result'])
        self.assertEqual(len(second['entries']), 5)
        self.assertIsNone(second['next_offset'])

    def test_read_is_paginated_and_capped(self):
        page = json.loads(self.source.execute({'op': 'read', 'path': 'a.py', 'start': 1, 'end': 5})['result'])
        self.assertEqual(len(page['lines']), 5)
        self.assertEqual(page['lines'][0], '1: line 1')
        self.assertEqual(page['next_line'], 6)
        page = json.loads(self.source.execute({'op': 'read', 'path': 'a.py'})['result'])
        self.assertEqual(len(page['lines']), 200)
        self.assertEqual(page['next_line'], 201)
        page = json.loads(self.source.execute({'op': 'read', 'path': 'a.py', 'start': 200, 'end': 999})['result'])
        self.assertEqual(len(page['lines']), 51)
        self.assertIsNone(page['next_line'])

    def test_search_is_paginated(self):
        first = json.loads(self.source.execute({'op': 'search', 'query': 'needle'})['result'])
        self.assertEqual(len(first['matches']), 100)
        self.assertEqual(first['next_offset'], 100)
        second = json.loads(self.source.execute({'op': 'search', 'query': 'needle', 'offset': 100})['result'])
        self.assertEqual(len(second['matches']), 20)
        self.assertIsNone(second['next_offset'])
        self.assertEqual(second['matches'][0]['path'], 'dir/b.py')
        self.assertIn('sha256', second['matches'][0])

    def test_path_traversal_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'inside the repository'):
            self.source.execute({'op': 'read', 'path': '../secret.txt'})
        with self.assertRaisesRegex(ValueError, 'inside the repository'):
            self.source.execute({'op': 'read', 'path': 'dir/../../secret.txt'})
        with self.assertRaisesRegex(ValueError, 'outside indexed source'):
            self.source.text('missing.txt')

    def test_budget_clips_result_and_stops(self):
        with patch.object(source_module, 'MAX_SOURCE_CHARS', 80):
            record = self.source.execute({'op': 'read', 'path': 'a.py'})
            self.assertTrue(record['truncated'])
            self.assertEqual(self.source.used, 80)
            result = json.loads(record['result'])
            self.assertTrue(result.get('budget_exhausted'))

    def test_fingerprint_changes_on_add_modify_delete(self):
        original = self.source.fingerprint
        (self.root / 'new.py').write_text('new\n', encoding='utf-8')
        added = Source(self.root)
        self.assertNotEqual(added.fingerprint, original)
        (self.root / 'a.py').write_text('changed\n', encoding='utf-8')
        modified = Source(self.root)
        self.assertNotEqual(modified.fingerprint, added.fingerprint)
        (self.root / 'new.py').unlink()
        deleted = Source(self.root)
        self.assertNotEqual(deleted.fingerprint, modified.fingerprint)

    def test_collect_multi_round_and_final_instruction(self):
        class Scripted:
            def __init__(self):
                self.replies = [
                    '{"actions":[{"op":"search","query":"needle"}]}',
                    '{"done":true}',
                ]

            def complete(self, messages, stage):
                return self.replies.pop(0)

        trace = []
        messages = self.source.collect(Scripted(), [{'role': 'user', 'content': 'input'}], 'extract', trace)
        self.assertEqual(len(trace), 2)
        self.assertEqual(self.source.rounds, 2)
        self.assertIn('检索阶段结束', messages[-1]['content'])
        self.assertTrue(any('matches' in message['content'] for message in messages if message['role'] == 'user'))


if __name__ == '__main__':
    unittest.main()
