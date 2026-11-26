import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import src.main as cli
from src.agents.oracle_designer import digest, process_oracle
from src.config import RESOURCES
from src.toolbox.source import CLASSIFICATION_VERSION, RETRIEVAL_VERSION, VERSION, Source
from src.toolbox.validation import (
    oracle_status,
    schemas,
    validate_oracle,
    validate_selection,
)
from tests.test_agent import example


CVE = example()['cve_id']


def request(rid='attack-1', actor='attacker', method='PATCH', endpoint='/v1/models/{id}'):
    req = copy.deepcopy(example()['attacker_requests'][0])
    req.update(id=rid, actor=actor, method=method, endpoint=endpoint)
    return req


def access_check(cid, subject, phase, request_id, action, policy='deny rule'):
    return {
        'id': cid,
        'subject': subject,
        'phase': phase,
        'access': {
            'action': action,
            'http_method': 'PATCH',
            'request_id': request_id,
            'restricted_fields': ['name'],
        },
        'object': {
            'resource': 'target_model',
            'identifier': '$target_model.id',
            'owner': 'victim',
            'scope': 'org_id=$shared_org.id',
            'precondition': 'exists',
        },
        'expected_decision': 'deny',
        'policy_basis': policy,
    }


def observation(oid, timing, check, actor, target='$target_model.id'):
    return {
        'id': oid,
        'timing': timing,
        'access_check': check,
        'api': None,
        'query': 'select * from model_mapping where id = :target',
        'extract': {'name': 'name'},
        'assertion': 'the target field changes',
        'actor': actor,
        'target': {'id': target},
    }


def verifier(kind, observations, unresolved=None):
    return {
        'type': kind,
        'observations': observations,
        'success_condition': 'The protected effect is observed on the same target.',
        'unresolved_conditions': unresolved or [],
    }


def design_o1():
    template = {
        'type': 'O1',
        'goal': 'Viewer updates a model owned by another user',
        'subjects': {'attacker': 'viewer', 'victim': 'model owner'},
        'resources': {'target_model': 'model owned by victim in the shared org'},
        'access_checks': [
            access_check('ac1', 'attacker', 'operation', 'attack-1', 'update model')
        ],
        'permission_checks': [],
        'controls': {'positive': [], 'negative': []},
        'attack_request': [request()],
        'expected_policy': {'rule': 'viewer may not update models', 'basis': 'roles.ts'},
    }
    return {'cve_id': CVE, 'oracles': [{
        'id': 'o1',
        'template': template,
        'verifier': verifier('UPDATE', [
            observation('before', 'before_attack', 'ac1', 'victim'),
            observation('after', 'after_attack', 'ac1', 'victim'),
        ]),
    }]}


def design_o2():
    template = {
        'type': 'O2',
        'goal': 'Attacker obtains an admin capability and beneficiary uses it',
        'subjects': {
            'attacker': 'low-privilege user',
            'victim': 'target account',
            'beneficiary': 'account that receives the capability',
        },
        'resources': {'target_account': 'victim account'},
        'access_checks': [
            access_check('ac1', 'attacker', 'acquisition', 'attack-1', 'grant role'),
            access_check('ac2', 'beneficiary', 'use', 'use-1', 'use admin capability'),
        ],
        'permission_checks': [],
        'controls': {'positive': [], 'negative': []},
        'attack_request': [request('attack-1', 'attacker', 'PATCH', '/users/{id}/role')],
        'capability_change': 'attacker grants beneficiary an admin role',
        'capability_use_requests': [request('use-1', 'beneficiary', 'GET', '/admin')],
        'expected_policy': {'rule': 'role changes require admin', 'basis': None},
    }
    return {'cve_id': CVE, 'oracles': [{
        'id': 'o1',
        'template': template,
        'verifier': verifier('PRIVILEGE_USE', [
            observation('before', 'before_acquisition', 'ac1', 'attacker'),
            observation('use', 'after_use', 'ac2', 'beneficiary'),
        ]),
    }]}


def design_o3():
    template = {
        'type': 'O3',
        'goal': 'Victim state contaminates a later attacker request',
        'subjects': {'attacker': 'attacker', 'victim': 'victim'},
        'resources': {'shared_worker': 'worker shared across requests'},
        'access_checks': [
            access_check('ac1', 'victim', 'baseline', 'victim-1', 'establish identity'),
            access_check('ac2', 'attacker', 'attack', 'attack-1', 'consume shared identity'),
            access_check('ac3', 'attacker', 'effect', 'attack-1', 'read protected data'),
        ],
        'permission_checks': [],
        'controls': {'positive': [], 'negative': []},
        'attack_request': [request('attack-1', 'attacker', 'GET', '/protected')],
        'victim_requests': [request('victim-1', 'victim', 'POST', '/login')],
        'shared_state_conditions': 'the same worker thread retains victim identity',
        'schedule': {'relation': 'before', 'condition': 'same worker', 'reset': None, 'attempt_limit': 1},
        'expected_policy': {'rule': 'identity must not leak across requests', 'basis': None},
    }
    return {'cve_id': CVE, 'oracles': [{
        'id': 'o1',
        'template': template,
        'verifier': verifier('STATE_ISOLATION', [
            observation('baseline', 'before_attack', 'ac1', 'victim'),
            observation('effect', 'after_attack', 'ac3', 'attacker'),
        ]),
    }]}


def selection(status='selected', selected='O1'):
    candidates = [
        {'template': 'O1', 'applicable': True, 'evidence': ['e1'], 'gaps': [], 'rejected_reason': None},
        {'template': 'O2', 'applicable': False, 'evidence': [], 'gaps': [], 'rejected_reason': 'no capability use'},
        {'template': 'O3', 'applicable': False, 'evidence': [], 'gaps': [], 'rejected_reason': 'no shared state'},
    ]
    if status == 'selected':
        for candidate in candidates:
            if candidate['template'] == selected:
                candidate.update(applicable=True, rejected_reason=None)
            else:
                candidate.update(applicable=False, rejected_reason='less suitable')
    elif status == 'ambiguous':
        candidates[0].update(applicable=True, rejected_reason=None)
        candidates[1].update(applicable=True, rejected_reason=None)
        selected = None
    else:
        for candidate in candidates:
            candidate.update(applicable=False, rejected_reason='missing evidence')
        selected = None
    return {
        'cve_id': CVE,
        'status': status,
        'selected_template': selected,
        'core_effect': 'core impact',
        'candidates': candidates,
        'selection_basis': 'selection basis',
        'gaps': [] if status != 'incomplete' else ['insufficient evidence'],
    }


class OracleTests(unittest.TestCase):
    def test_selection_requires_one_consistent_choice(self):
        value = selection()
        validate_selection(value, CVE)
        bad = copy.deepcopy(value)
        bad['selected_template'] = 'O2'
        with self.assertRaisesRegex(ValueError, 'selected template'):
            validate_selection(bad, CVE)
        bad = copy.deepcopy(value)
        bad['status'] = 'ambiguous'
        bad['selected_template'] = None
        with self.assertRaisesRegex(ValueError, 'at least two'):
            validate_selection(bad, CVE)
        bad = copy.deepcopy(value)
        bad['status'] = 'incomplete'
        bad['selected_template'] = None
        with self.assertRaisesRegex(ValueError, 'gap'):
            validate_selection(bad, CVE)

    def test_three_templates_and_access_bindings(self):
        for value, kind in ((design_o1(), 'O1'), (design_o2(), 'O2'), (design_o3(), 'O3')):
            select = selection('selected', kind)
            validate_oracle(value, example(), select)
            self.assertIn(value['oracles'][0]['template']['type'], {'O1', 'O2', 'O3'})

        bad = copy.deepcopy(design_o1())
        bad['oracles'][0]['template']['capability_change'] = 'not allowed for O1'
        with self.assertRaises(ValueError):
            validate_oracle(bad, example(), selection())

        bad = copy.deepcopy(design_o1())
        bad['oracles'][0]['template']['access_checks'][0]['subject'] = 'unknown'
        with self.assertRaisesRegex(ValueError, 'undeclared subject'):
            validate_oracle(bad, example(), selection())

        bad = copy.deepcopy(design_o1())
        bad['oracles'][0]['template']['access_checks'][0]['expected_decision'] = 'allow'
        with self.assertRaisesRegex(ValueError, 'expect deny'):
            validate_oracle(bad, example(), selection())

        bad = copy.deepcopy(design_o1())
        bad['oracles'][0]['verifier']['observations'][0]['access_check'] = 'missing'
        with self.assertRaisesRegex(ValueError, 'access check'):
            validate_oracle(bad, example(), selection())

    def test_o2_and_o3_specific_constraints(self):
        select_o2 = selection('selected', 'O2')
        validate_oracle(design_o2(), example(), select_o2)
        bad = copy.deepcopy(design_o2())
        del bad['oracles'][0]['template']['subjects']['beneficiary']
        with self.assertRaisesRegex(ValueError, 'beneficiary'):
            validate_oracle(bad, example(), select_o2)
        bad = copy.deepcopy(design_o2())
        bad['oracles'][0]['template']['access_checks'][1]['phase'] = 'acquisition'
        with self.assertRaisesRegex(ValueError, 'acquisition and use'):
            validate_oracle(bad, example(), select_o2)

        select_o3 = selection('selected', 'O3')
        validate_oracle(design_o3(), example(), select_o3)
        bad = copy.deepcopy(design_o3())
        bad['oracles'][0]['template']['access_checks'] = [
            check for check in bad['oracles'][0]['template']['access_checks'] if check['phase'] != 'baseline'
        ]
        with self.assertRaisesRegex(ValueError, 'baseline'):
            validate_oracle(bad, example(), select_o3)
        bad = copy.deepcopy(design_o3())
        del bad['oracles'][0]['template']['schedule']['reset']
        with self.assertRaises(ValueError):
            validate_oracle(bad, example(), select_o3)

    def test_status_is_ready_only_without_gaps(self):
        select = selection()
        value = design_o1()
        self.assertEqual(oracle_status(select, value), 'ready')
        value['oracles'][0]['template']['access_checks'][0]['policy_basis'] = None
        self.assertEqual(oracle_status(select, value), 'incomplete')
        value = design_o1()
        value['oracles'][0]['verifier']['observations'][0]['query'] = None
        self.assertEqual(oracle_status(select, value), 'incomplete')
        value = design_o1()
        value['oracles'][0]['verifier']['unresolved_conditions'] = ['missing read channel']
        self.assertEqual(oracle_status(select, value), 'incomplete')
        select = selection('ambiguous')
        self.assertEqual(oracle_status(select, {'cve_id': CVE, 'oracles': []}), 'incomplete')

    def test_stage_dispatch_and_counts(self):
        cases = [
            ('tp', 'success', 'ready', 1, 0, 0),
            ('oracle', 'success', 'ready', 0, 1, 0),
            ('all', 'success', 'ready', 1, 1, 0),
            ('all', 'success', 'incomplete', 1, 1, 0),
            ('all', 'failed', 'ready', 1, 0, 1),
            ('all', 'success', 'failed', 1, 1, 1),
        ]
        for stage, tp_status, oracle_status_value, tp_count, oracle_count, exit_code in cases:
            with patch('sys.argv', ['agent.py', '--stage', stage, '--cve', CVE]), \
                 patch.object(cli, 'process', return_value=tp_status) as first, \
                 patch.object(cli, 'process_oracle', return_value=oracle_status_value) as second:
                self.assertEqual(cli.main(), exit_code)
                self.assertEqual(first.call_count, tp_count)
                self.assertEqual(second.call_count, oracle_count)

    def make_case(self, root):
        cve = CVE
        folder = root / cve
        folder.mkdir()
        raw = json.dumps({'description': 'Oracle source case'})
        source = folder / (cve + '.json')
        source.write_text(raw, encoding='utf-8')
        (folder / 'output.json').write_text(
            json.dumps({**example(), 'classification': ['TP1']}), encoding='utf-8'
        )
        (folder / 'run.json').write_text(
            json.dumps({
                'status': 'success',
                'input_sha256': digest(raw),
                'pipeline_version': VERSION,
                'classification_version': CLASSIFICATION_VERSION,
                'retrieval_version': RETRIEVAL_VERSION,
                'source_sha256': Source(None).fingerprint,
                'prompt_sha256': digest((RESOURCES / 'prompts/trigger.md').read_text(encoding='utf-8')),
                'schema_sha256': digest(json.dumps(schemas()[1], sort_keys=True)),
            }),
            encoding='utf-8',
        )
        (folder / 'extraction_analysis.md').write_text('Evidence', encoding='utf-8')
        return source, folder

    def test_cache_failure_preservation_and_selection_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, folder = self.make_case(root)

            class Client:
                key = 'secret'
                model = 'fake'

                def __init__(self):
                    self.calls = []
                    self.replies = [
                        json.dumps({'selection': selection(), 'analysis': 'selection'}),
                        json.dumps({'oracle': design_o1(), 'analysis': 'oracle'}),
                    ]

                def complete(self, messages, stage):
                    self.calls.append(stage)
                    return self.replies.pop(0)

            client = Client()
            self.assertEqual(process_oracle(source, root, lambda: client), 'ready')
            oracle = folder / 'oracle.json'
            saved = oracle.read_bytes()
            self.assertEqual(process_oracle(source, root, lambda: self.fail('cache must skip')), 'skipped')

            with patch.object(Client, 'complete', side_effect=RuntimeError('failed')):
                self.assertEqual(process_oracle(source, root, Client, True), 'failed')
            self.assertEqual(saved, oracle.read_bytes())

            source.write_text(json.dumps({'description': 'changed'}), encoding='utf-8')
            self.assertEqual(process_oracle(source, root, lambda: self.fail('stale TP must not call model')), 'failed')

            source.write_text(json.dumps({'description': 'Oracle source case'}), encoding='utf-8')
            folder.joinpath('oracle.json').unlink()
            class ReusedClient:
                key = 'secret'
                model = 'fake'

                def __init__(self):
                    self.calls = []

                def complete(self, messages, stage):
                    self.calls.append(stage)
                    return json.dumps({'oracle': design_o1(), 'analysis': 'oracle'})

            reused = ReusedClient()
            self.assertEqual(process_oracle(source, root, lambda: reused), 'ready')
            self.assertEqual(reused.calls, ['oracle'])

    def test_ambiguous_selection_writes_empty_oracle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, folder = self.make_case(root)

            class Client:
                key = 'secret'
                model = 'fake'

                def __init__(self):
                    self.calls = []

                def complete(self, messages, stage):
                    self.calls.append(stage)
                    return json.dumps({'selection': selection('ambiguous'), 'analysis': 'ambiguous'})

            client = Client()
            self.assertEqual(process_oracle(source, root, lambda: client), 'incomplete')
            self.assertEqual(client.calls, ['oracle_select'])
            self.assertEqual(json.loads((folder / 'oracle.json').read_text(encoding='utf-8'))['oracles'], [])
            self.assertEqual(json.loads((folder / 'oracle_run.json').read_text(encoding='utf-8'))['status'], 'incomplete')

    def test_targeted_repair_for_legacy_format_failures(self):
        bare = json.dumps(design_o1()['oracles'][0]['template'])
        extra = json.dumps({'oracle': design_o1(), 'analysis': 'x', '_': 1})
        for malformed in ([bare], [extra], [bare, extra]):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, folder = self.make_case(root)

                class Client:
                    key = 'secret'
                    model = 'fake'

                    def __init__(self):
                        self.calls = []
                        self.replies = [
                            json.dumps({'selection': selection(), 'analysis': 'selection'}),
                            *malformed,
                            json.dumps({'oracle': design_o1(), 'analysis': 'oracle'}),
                        ]

                    def complete(self, messages, stage):
                        self.calls.append(stage)
                        return self.replies.pop(0)

                client = Client()
                self.assertEqual(process_oracle(source, root, lambda: client), 'ready')
                self.assertEqual(client.calls.count('oracle'), len(malformed) + 1)

    def test_verifier_nested_in_template_is_moved_back(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, folder = self.make_case(root)
            value = design_o1()
            item = value['oracles'][0]
            item['template']['verifier'] = item.pop('verifier')

            class Client:
                key = 'secret'
                model = 'fake'

                def __init__(self):
                    self.calls = []
                    self.replies = [
                        json.dumps({'selection': selection(), 'analysis': 'selection'}),
                        json.dumps({'oracle': value, 'analysis': 'oracle'}),
                    ]

                def complete(self, messages, stage):
                    self.calls.append(stage)
                    return self.replies.pop(0)

            self.assertEqual(process_oracle(source, root, Client), 'ready')
            saved = json.loads((folder / 'oracle.json').read_text(encoding='utf-8'))
            self.assertIn('verifier', saved['oracles'][0])
            self.assertNotIn('verifier', saved['oracles'][0]['template'])


if __name__ == '__main__':
    unittest.main()
