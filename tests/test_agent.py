import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

import src.main as agent
from src.toolbox import llm_client
from src.agents import trigger_extractor


def example():
    return {
        'cve_id': 'CVE-2024-10762', 'victim_requests': [],
        'attacker_requests': [{'id': 'r1', 'method': 'DELETE', 'handler': None,
            'endpoint': '/api/v1/evaluators/{id}',
            'params': {'path': {'id': '$id'}, 'query': {}},
            'headers': None, 'body': None,
            'response': {'status_code': 200, 'headers': None, 'body': None}}],
        'trigger_points': [{'request_id': 'r1', 'locations': ['api'], 'field': None, 'action': 'invoke', 'before': None, 'after': None}],
        'interaction': {'victim_request_required': False, 'relation': None, 'condition': None}}


class FakeClient:
    model = 'fake'
    key = 'test-secret'

    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def complete(self, messages, stage):
        if self.fail:
            raise RuntimeError('simulated failure')
        self.calls.append({'stage': stage})
        data = example()
        if stage == 'extract':
            return json.dumps({'extraction': data, 'analysis': '状态码为代码证据。'})
        raise AssertionError('Classification must not call LLM')



class AgentTests(unittest.TestCase):
    def test_flat_evidence_forwarded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = {
                'description': 'DESC_SENTINEL',
                'patch_commits': [{'content': 'PATCH_SENTINEL'}],
                'sec_adv': [{'content': 'ADV_SENTINEL'}],
                'sw_version': 'v1',
                'dir_tree': '.\n└── views.py',
            }
            source = root / 'CVE-2024-10762.json'
            source.write_text(json.dumps(evidence), encoding='utf-8')
            client = FakeClient()
            with patch.object(client, 'complete', wraps=client.complete) as complete:
                self.assertEqual(trigger_extractor.process(source, root / 'out', lambda: client), 'success')
                messages = complete.call_args.args[0]
                self.assertIn('DESC_SENTINEL', messages[1]['content'])
                self.assertIn('PATCH_SENTINEL', messages[1]['content'])
                self.assertIn('ADV_SENTINEL', messages[1]['content'])
                self.assertNotIn('patch_commits', messages[1]['content'])
                self.assertIn('vulnerability', messages[1]['content'])

    def test_results_directory_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cve = 'CVE-2024-10762'
            folder = root / cve
            folder.mkdir()
            source = folder / (cve + '.json')
            source.write_text('{}')
            for extra in ([], ['--cve', cve], ['--input', str(source)]):
                with patch('sys.argv', ['agent.py', '--results-dir', str(root), *extra]), \
                     patch('src.main.process', return_value='success') as process:
                    self.assertEqual(agent.main(), 0)
                    self.assertEqual(process.call_args.args[:2], (source, root))

    def test_flat_input_directory_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / 'inputs'
            inputs.mkdir()
            first = inputs / 'CVE-2024-10762.json'
            second = inputs / 'CVE-2024-10763.json'
            first.write_text('{}')
            second.write_text('{}')
            output = root / 'out'
            with patch('sys.argv', ['agent.py', '--input-dir', str(inputs), '--results-dir', str(output)]), \
                 patch('src.main.process', return_value='success') as process:
                self.assertEqual(agent.main(), 0)
                self.assertEqual([call.args[0] for call in process.call_args_list], [first, second])
                self.assertEqual(process.call_args.args[1], output)

    def test_source_backed_body_fixture(self):
        data = example()
        request = data['attacker_requests'][0]
        request.update(method='POST', handler='delete_user',
            endpoint='/api/v1/worlds/{world_id}/delete_user',
            params={'path': {'world_id': '$world_id'}, 'query': {}},
            body={'format': 'application/json', 'fields': {'user_id': '$target_user_id'}},
            response={'status_code': 204, 'headers': None, 'body': None})
        data['trigger_points'][0].update(locations=['body'], field='user_id',
            action='modify', after='$target_user_id')
        agent.validate(data, agent.schemas()[0], data['cve_id'])
        self.assertEqual(agent.classify(data)[0], ['TP3'])
        data['trigger_points'][0]['after'] = '$other_id'
        with self.assertRaisesRegex(ValueError, 'conflicts with body'):
            agent.validate(data, agent.schemas()[0], data['cve_id'])

    def test_save_skip_and_preserve_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'CVE-2024-10762.json'
            source.write_text(json.dumps({'description': 'RAW_SOURCE_SENTINEL'}))
            result = root / 'results'
            self.assertEqual(trigger_extractor.process(source, result, FakeClient), 'success')
            output = result / 'CVE-2024-10762' / 'output.json'
            original = output.read_bytes()
            self.assertEqual(trigger_extractor.process(source, result, lambda: self.fail('must not call')), 'skipped')
            self.assertEqual(trigger_extractor.process(source, result, lambda: FakeClient(True), True), 'failed')
            self.assertEqual(original, output.read_bytes())

    def test_static_trigger_mapping(self):
        for location, tp in [('url', 'TP2'), ('body', 'TP3'), ('header', 'TP4')]:
            data = example()
            data['trigger_points'][0].update(locations=[location], action='replace', field='x')
            self.assertEqual(agent.classify(data)[0], [tp])
        data['trigger_points'][0]['locations'] = ['url', 'body']
        self.assertEqual(agent.classify(data)[0], ['TP3'])
        data['trigger_points'] = []
        self.assertEqual(agent.classify(data)[0], [])
        data['interaction']['victim_request_required'] = True
        self.assertEqual(agent.classify(data)[0], ['TP5'])

    def test_invalid_trigger_reference_and_action(self):
        data = example()
        data['trigger_points'][0]['request_id'] = 'missing'
        with self.assertRaises(ValueError):
            agent.validate(data, agent.schemas()[0], data['cve_id'])

    def test_dependent_invoke_is_not_tp1(self):
        data = example()
        data['interaction'].update(victim_request_required=True, relation='before', condition='shared thread')
        self.assertEqual(agent.classify(data)[0], ['TP5'])
        with self.assertRaisesRegex(ValueError, 'independence'):
            agent.validate(data, agent.schemas()[0], data['cve_id'])
        data['trigger_points'] = []
        agent.validate(data, agent.schemas()[0], data['cve_id'])
        self.assertEqual(agent.classify(data)[0], ['TP5'])
        data['interaction']['victim_request_required'] = None
        data['trigger_points'] = example()['trigger_points']
        self.assertEqual(agent.classify(data)[0], [])

    def test_dependency_preserves_field_mutations(self):
        for location, tp in [('url', 'TP2'), ('body', 'TP3'), ('header', 'TP4')]:
            data = example()
            data['interaction']['victim_request_required'] = True
            data['trigger_points'][0].update(locations=[location], action='modify')
            agent.validate(data, agent.schemas()[0], data['cve_id'])
            self.assertEqual(agent.classify(data)[0], ['TP5'])
            self.assertEqual(data['trigger_points'][0]['locations'], [location])
        data = example()
        data['trigger_points'][0]['action'] = 'add'
        with self.assertRaises(ValueError):
            agent.validate(data, agent.schemas()[0], data['cve_id'])

    def test_json_repair(self):
        client = Mock()
        client.complete.side_effect = ['not json', '{"ok": true}']
        trace = []
        result = llm_client.run_stage(client, [], lambda x: None, 'extract', trace)
        self.assertTrue(result['ok'])
        self.assertEqual(len(trace), 2)

    def test_json_with_trailing_data(self):
        client = Mock()
        client.complete.side_effect = ['{"ok": true}\n{"extra": 1}', '{"ok": true}']
        trace = []
        result = llm_client.run_stage(client, [], lambda x: None, 'extract', trace)
        self.assertTrue(result['ok'])
        self.assertEqual(len(trace), 1)
        self.assertEqual(llm_client.parse_json('{"oracle": {}},"analysis": "x"}'),
                         {'oracle': {}, 'analysis': 'x'})
        self.assertEqual(llm_client.parse_json('{"a": 1}{"b": 2}'), {'a': 1, 'b': 2})
        self.assertEqual(llm_client.parse_json('{"oracle": {"cve_id": "x"}'),
                         {'oracle': {'cve_id': 'x'}})

    def test_unlocated_target_is_candidate_not_direct_invoke(self):
        data = example()
        data['trigger_points'][0].update(locations=['url', 'body'], action='modify', field=None)
        data['attacker_requests'][0].update(endpoint=None, params={'path': None, 'query': None})
        agent.validate(data, agent.schemas()[0], data['cve_id'])
        result, analysis = agent.classify(data)
        self.assertEqual(result, ['TP3'])
        self.assertIn('TP2', analysis)
        data['trigger_points'].append(example()['trigger_points'][0])
        with self.assertRaisesRegex(ValueError, 'same request'):
            agent.validate(data, agent.schemas()[0], data['cve_id'])

    def test_retry_and_auth_failure(self):
        transient = Mock(status_code=429)
        success = Mock(status_code=200, ok=True)
        success.json.return_value = {'choices': [{'message': {'content': '{}'}, 'finish_reason': 'stop'}]}
        with patch('src.toolbox.llm_client.requests.post', side_effect=[transient, success]) as post, patch('src.toolbox.llm_client.time.sleep'):
            self.assertEqual(agent.Client('secret').complete([], 'test'), '{}')
            self.assertEqual(post.call_count, 2)
        with patch('src.toolbox.llm_client.requests.post', return_value=Mock(status_code=401, ok=False)) as post:
            with self.assertRaisesRegex(RuntimeError, '401'):
                agent.Client('secret').complete([], 'test')
            self.assertEqual(post.call_count, 1)
        truncated = Mock(status_code=200, ok=True)
        truncated.json.return_value = {'choices': [{'message': {'content': '{}'}, 'finish_reason': 'length'}]}
        with patch('src.toolbox.llm_client.requests.post', return_value=truncated):
            with self.assertRaisesRegex(RuntimeError, '长度限制'):
                agent.Client('secret').complete([], 'oracle')

    def test_priority_over_candidate_locations(self):
        data = example()
        data['trigger_points'][0].update(locations=['url', 'body', 'header'], action='unknown', field=None)
        agent.validate(data, agent.schemas()[0], data['cve_id'])
        result, analysis = agent.classify(data)
        self.assertEqual(result, ['TP4'])
        self.assertIn('TP2', analysis)
        self.assertIn('TP3', analysis)
        data['trigger_points'].append(dict(data['trigger_points'][0]))
        self.assertEqual(agent.classify(data)[0], ['TP4'])
        data['trigger_points'][0]['locations'] = []
        data['trigger_points'] = data['trigger_points'][:1]
        self.assertEqual(agent.classify(data)[0], [])

    def test_priority_matrix(self):
        data = example()
        data['interaction']['victim_request_required'] = True
        result, analysis = agent.classify(data)
        self.assertEqual(result, ['TP5'])
        self.assertIn('TP1', analysis)

        for locations, expected in [
            (['url', 'header'], 'TP4'),
            (['url', 'body'], 'TP3'),
            (['body', 'header'], 'TP4'),
            (['url', 'body', 'header'], 'TP4'),
        ]:
            data = example()
            data['trigger_points'][0].update(locations=locations, action='modify')
            self.assertEqual(agent.classify(data)[0], [expected])

        data = example()
        data['interaction']['victim_request_required'] = True
        data['trigger_points'].append({
            'request_id': 'r1', 'locations': ['url', 'body', 'header'],
            'field': 'x', 'action': 'modify', 'before': None, 'after': None,
        })
        result, analysis = agent.classify(data)
        self.assertEqual(result, ['TP5'])
        for label in ('TP1', 'TP2', 'TP3', 'TP4', 'TP5'):
            self.assertIn(label, analysis)

        data = example()
        data['trigger_points'] = []
        data['interaction']['victim_request_required'] = False
        self.assertEqual(agent.classify(data)[0], [])

    def test_consistency(self):
        data = example()
        data['classification'] = ['TP2']
        with self.assertRaisesRegex(ValueError, 'static rules'):
            agent.validate(data, agent.schemas()[1], data['cve_id'])


if __name__ == '__main__':
    unittest.main()
