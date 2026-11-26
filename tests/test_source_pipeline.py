import json
import tempfile
import unittest
from pathlib import Path

from src.agents.oracle_designer import process_oracle
from src.agents.trigger_extractor import process
from tests.test_agent import example
from tests.test_oracle import design_o1, selection


class ScriptedClient:
    model = 'fake'
    key = 'secret'

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []
        self.messages = []

    def complete(self, messages, stage):
        self.calls.append(stage)
        self.messages.append(messages)
        if not self.replies:
            raise AssertionError('unexpected model call')
        return self.replies.pop(0)


class SourcePipelineTests(unittest.TestCase):
    def make_case(self, root):
        repo = root / 'repo'
        (repo / 'src').mkdir(parents=True)
        (repo / 'src' / 'app.py').write_text('def handler():\n    return 1\n', encoding='utf-8')
        source = root / 'CVE-2024-10762.json'
        source.write_text(json.dumps({
            'description': 'source-backed case',
            'repo_path': 'repo',
            'dir_tree': '.\n└── src\n    └── app.py',
        }), encoding='utf-8')
        results = root / 'out'
        return repo, source, results

    def test_tp_retrieval_cache_invalidation_and_failure_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, source, results = self.make_case(root)
            first = ScriptedClient([
                '{"actions":[{"op":"read","path":"src/app.py","start":1,"end":50}]}',
                '{"done":true}',
                json.dumps({'extraction': example(), 'analysis': '源码证据：src/app.py:1'}),
            ])
            self.assertEqual(process(source, results, lambda: first), 'success')
            output = results / 'CVE-2024-10762' / 'output.json'
            saved = output.read_bytes()
            evidence = json.loads((results / 'CVE-2024-10762' / 'source_evidence.json').read_text(encoding='utf-8'))
            self.assertEqual(len(evidence), 1)
            self.assertEqual(evidence[0]['action']['path'], 'src/app.py')
            self.assertIn('src/app.py', evidence[0]['result'])

            self.assertEqual(process(source, results, lambda: self.fail('cache must skip')), 'skipped')

            (repo / 'src' / 'app.py').write_text('def handler():\n    return 2\n', encoding='utf-8')
            self.assertEqual(process(source, results, lambda: (_ for _ in ()).throw(RuntimeError('source changed'))), 'failed')
            self.assertEqual(saved, output.read_bytes())

            second = ScriptedClient([
                '{"actions":[{"op":"search","query":"return"}]}',
                '{"done":true}',
                json.dumps({'extraction': example(), 'analysis': '源码证据：src/app.py:2'}),
            ])
            self.assertEqual(process(source, results, lambda: second), 'success')
            updated = json.loads((results / 'CVE-2024-10762' / 'source_evidence.json').read_text(encoding='utf-8'))
            self.assertEqual(updated[0]['action']['op'], 'search')

    def test_oracle_reuses_tp_reads_and_requires_fresh_tp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, source, results = self.make_case(root)
            tp = ScriptedClient([
                '{"actions":[{"op":"list","path":"src"}]}',
                '{"done":true}',
                json.dumps({'extraction': example(), 'analysis': 'source evidence'}),
            ])
            self.assertEqual(process(source, results, lambda: tp), 'success')

            oracle = ScriptedClient([
                '{"actions":[{"op":"read","path":"src/app.py"}]}',
                '{"done":true}',
                json.dumps({'selection': selection(), 'analysis': 'selection evidence'}),
                '{"actions":[{"op":"search","query":"return"}]}',
                '{"done":true}',
                json.dumps({'oracle': design_o1(), 'analysis': 'Oracle source evidence'}),
            ])
            self.assertEqual(process_oracle(source, results, lambda: oracle), 'ready')
            folder = results / 'CVE-2024-10762'
            combined = json.loads((folder / 'oracle_source_evidence.json').read_text(encoding='utf-8'))
            self.assertTrue(combined['tp_reads'])
            self.assertTrue(combined['oracle_reads'])
            self.assertIn('source_evidence', oracle.messages[0][1]['content'])

            saved = (folder / 'oracle.json').read_bytes()
            (repo / 'src' / 'app.py').write_text('changed after TP\n', encoding='utf-8')
            self.assertEqual(
                process_oracle(source, results, lambda: self.fail('stale TP must not call model')),
                'failed',
            )
            self.assertEqual(saved, (folder / 'oracle.json').read_bytes())


if __name__ == '__main__':
    unittest.main()
