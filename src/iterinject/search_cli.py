"""Explicit search preflight and composition; no model side effects on import."""
from __future__ import annotations
from copy import deepcopy
import json
import os
from pathlib import Path
from uuid import uuid4
from .core.types import TargetSpec
from .seeds.catalog import SeedCatalog,canonical_hash
from .models import ModelConfig

ROLES=('victim','optimizer','simulation','initializer','synthesis')


class RecordedModelClient:
    """Persist each model interface call before the caller advances the search."""

    def __init__(self, client, role, path):
        self.client = client
        self.role = role
        self.path = path

    def __getattr__(self, name):
        return getattr(self.client, name)

    def complete(self, messages):
        from .core.logging import _append_record, serialize
        from .models import _redact
        start = len(self.client.call_records)
        config = self.client.config
        config = config.to_dict() if hasattr(config, 'to_dict') else dict(config)
        failure = None
        try:
            return self.client.complete(messages)
        except Exception as error:
            failure = getattr(error, 'failure', None)
            raise
        finally:
            records = self.client.call_records[start:]
            _append_record(self.path, {
                'record_id': uuid4().hex, 'role': self.role,
                'config': config,
                'messages': _redact(deepcopy(messages),os.environ.get(config.get('api_key_env',''))),
                'interface_calls': 1,
                'api_calls': sum(r.get('api_calls', 0) for r in records),
                'failure': serialize(failure), 'call_records': deepcopy(records),
            })


def saved_model_evidence(path):
    """Rebuild summaries from durable calls, including resumes without summary.json."""
    interfaces = {role: 0 for role in ROLES}
    usage = []
    if path.is_file():
        for line in path.read_text(encoding='utf-8').splitlines():
            event = json.loads(line)
            interfaces[event['role']] += event['interface_calls']
            for record in event['call_records']:
                raw = record.get('raw_response')
                usage.append({
                    'record_id': event['record_id'], 'role': event['role'],
                    'request_model': record.get('config', {}).get('model'),
                    'returned_model': raw.get('model') if isinstance(raw, dict) else None,
                    'usage': raw.get('usage') if isinstance(raw, dict) else None,
                    'api_calls': record.get('api_calls', 0),
                })
    return interfaces, usage


def prepare_search(args):
    from .cli import _json_file,_file_info,_code_info,_benchmark,_policy_from_mapping
    from .configuration import compose_search_configuration
    from .core.logging import _check_public_metadata
    from .adapters.injecagent.dataset import load_cases,INJECTION_PROTOCOL
    from .adapters.injecagent.diagnoser import load_diagnostic_preset,DIAGNOSTIC_VERSION
    from .adapters.injecagent.initializers import InjecAgentInitializer
    run_path=getattr(args,'run_config',None)
    if not run_path:raise ValueError('search requires --run-config')
    full_method,run_config,config=compose_search_configuration(
        _json_file(args.method_config),_json_file(run_path))
    benchmark=_json_file(args.benchmark_config)
    _check_public_metadata(benchmark)
    allowed={'adapter','attack','setting','prompt_type','scope_id','seed','victim','optimizer','simulation','initializer','synthesis','diagnostic_policy_status','diagnostic_version'}
    if set(benchmark)-allowed:raise ValueError('unsupported search benchmark fields')
    attack,setting,prompt_type=_benchmark(benchmark)
    from .adapters.injecagent.agent_prompts import PROMPT_DICT
    if prompt_type not in PROMPT_DICT:raise ValueError('unsupported benchmark prompt type')
    if 'scope_id' in benchmark and benchmark['scope_id']!=config.run.scope_id:
        raise ValueError('benchmark/run scope mismatch')
    if benchmark.get('diagnostic_version')!=DIAGNOSTIC_VERSION:
        raise ValueError('search diagnostic version mismatch')
    fixture_path=getattr(args,'fixture_script',None)
    fixture=_json_file(fixture_path) if fixture_path else None
    if (fixture is not None)!=(config.run.status=='fixture'):
        raise ValueError('fixture script and policy status must agree')
    models={}
    for role in ROLES:
        value=benchmark.get(role)
        if not isinstance(value,dict):raise ValueError(f'missing independent {role} model')
        value=dict(value)
        if role=='simulation':
            mode=value.pop('mode',None)
            if mode not in ('generate_on_miss','cache_only'):
                raise ValueError('simulation mode must be generate_on_miss or cache_only')
        try:models[role]=ModelConfig(role=role,**value)
        except (TypeError,ValueError) as exc:raise ValueError(f'invalid {role} model configuration: {exc}') from None
        if (models[role].model.startswith('fixture:'))!=(fixture is not None):
            raise ValueError('fixture model identity is incompatible with search mode')
    if fixture is not None:
        allowed_fixture={'schema_version','diagnostic_policy',*(r+'_responses' for r in ROLES)}
        if set(fixture)-allowed_fixture:raise ValueError('unsupported search fixture fields')
        _policy_from_mapping(fixture['diagnostic_policy'],fixture=True)
        for role in ROLES:
            responses=fixture.get(role+'_responses',[])
            if not isinstance(responses,list) or any(not isinstance(v,str) for v in responses):
                raise ValueError('fixture response scripts must be explicit text lists')
    else:
        _policy_from_mapping(load_diagnostic_preset())
    method=full_method.inner_loop
    catalog=SeedCatalog(args.seed_catalog)
    seeds=catalog.seeds_from_bindings(config.run.seed_bindings,fixture=fixture is not None,validate_assets=fixture is None)
    if fixture is None:
        initializer=InjecAgentInitializer(asset_root=catalog.asset_root())
        for seed in seeds:initializer.validate(seed)
    data_dir=Path(args.data_dir).expanduser().resolve(strict=True)
    manifest=_json_file(args.target_manifest)
    if set(manifest)!={'schema_version','scope_id','attack','setting','targets'} or manifest['schema_version']!='phase2-target-manifest-v1':
        raise ValueError('invalid target manifest fields')
    if (manifest['scope_id'],manifest['attack'],manifest['setting'])!=(config.run.scope_id,attack,setting):
        raise ValueError('incompatible target manifest scope')
    rows=manifest['targets']
    if not isinstance(rows,list) or not rows:raise ValueError('target manifest must be nonempty')
    if any(not isinstance(r,dict) or set(r)!={'target_id','source','tool_chain_signature'} for r in rows):
        raise ValueError('target manifest requires explicit ID/source/tool signature')
    cases=load_cases(data_dir,attack,setting,case_ids=tuple(r['target_id'] for r in rows))
    for row,case in zip(rows,cases):
        if row['source']!=case.source or row['tool_chain_signature']!=case.raw['Attacker Tools']:
            raise ValueError('target manifest case source/hash mismatch')
        if not any(s.initializer_kind!='unsupported' and s.target_binding in (None,case.case_id) for s in seeds):
            raise ValueError('target has no eligible initialized seed')
    files={name:_file_info(getattr(args,name)) for name in ('benchmark_config','method_config','seed_catalog','target_manifest')}
    files['run_config']=_file_info(run_path)
    if fixture_path:files['fixture_script']=_file_info(fixture_path)
    data_files={path.name:_file_info(path) for path in sorted(data_dir.glob('*.json'))}
    scope_snapshot={'scope_id':config.run.scope_id,'adapter':'injecagent','attack':attack,'setting':setting,
        'diagnostic_version':DIAGNOSTIC_VERSION,'input_version':INJECTION_PROTOCOL,
        'models':{r:models[r].to_dict() for r in ROLES},'manifest_sha256':files['target_manifest']['sha256']}
    identity={'source_sha256':_code_info()['source_file_sha256'],
        'files':{name:value['sha256'] for name,value in files.items()},
        'data':{name:value['sha256'] for name,value in data_files.items()},'scope_snapshot_sha256':canonical_hash(scope_snapshot)}
    return {'config':config,'benchmark':benchmark,'cases':cases,'seeds':seeds,'identity':identity,'method':method,
            'method_configuration':full_method,'run_configuration':run_config,
            'fixture':fixture,'catalog':catalog,'models':models,'files':files,'data_files':data_files,'scope_snapshot':scope_snapshot}


def run_search(args):
    from .cli import _FixtureClient,_build_remote_client,_policy_from_mapping
    from .adapters.injecagent.diagnoser import load_diagnostic_preset
    from .core.budget import RequestBudget,BudgetedClient
    from .core.search import SeedSearch
    from .core.seed_bank import SeedBank
    from .core.search_records import FileSearchRecorder
    from .execution import InjecAgentSeedExecutor
    from .seeds.synthesis import SeedSynthesizer
    p=prepare_search(args)
    config=p['config'];fixture=p['fixture'];benchmark=p['benchmark']
    metadata={'schema_version':'seed-search-v1','mode':'fixture' if fixture is not None else 'remote',
        'evaluation_scope':'fixture' if fixture is not None else ('engineering_smoke' if getattr(args,'engineering_smoke',False) else 'formal'),
        'identity':p['identity'],'scope_snapshot':p['scope_snapshot'],
        'method_configuration':p['method_configuration'].snapshot(),
        'run_configuration':p['run_configuration'].snapshot(),
        'files':p['files'],'data_files':p['data_files'],'models':{r:p['models'][r].to_dict() for r in ROLES}}
    recorder=FileSearchRecorder(args.output_dir,metadata,resume=getattr(args,'resume',False))
    budget=RequestBudget(config.run.max_api_requests)
    clients={}
    for role in ROLES:
        base=(_FixtureClient(role,fixture.get(role+'_responses',[])) if fixture is not None
              else _build_remote_client(role,{k:v for k,v in p['models'][role].to_dict().items() if k!='role'}))
        clients[role]=RecordedModelClient(
            BudgetedClient(base,budget,role=role,fixture=fixture is not None),
            role,recorder.run_dir/'model-calls.jsonl')
    policy=_policy_from_mapping(fixture['diagnostic_policy'],fixture=True) if fixture is not None else _policy_from_mapping(load_diagnostic_preset())
    executor=InjecAgentSeedExecutor(args.data_dir,benchmark,p['method'],recorder.run_dir/'units',clients=clients,
        diagnostic_policy=policy,mode='fixture' if fixture is not None else 'remote',
        evaluation_scope=metadata['evaluation_scope'],asset_root=p['catalog'].asset_root(),
        method_configuration=metadata['method_configuration'])
    state=recorder.checkpoint() if getattr(args,'resume',False) else None
    used_seed_ids={seed.seed_id for seed in p['seeds']}
    if state:
        for line in (recorder.run_dir/'synthesis.jsonl').read_text().splitlines():
            candidate=json.loads(line).get('candidate')
            if candidate:
                used_seed_ids.add(candidate['seed_id'])
        for seed in state['seed_bank']['seeds']:
            used_seed_ids.add(seed['seed_id'])
    counter={'n':max((int(seed_id[6:]) for seed_id in used_seed_ids
                     if seed_id.startswith('synth-') and seed_id[6:].isascii()
                     and seed_id[6:].isdigit()),default=0)}
    def next_seed_id():
        while True:
            counter['n']+=1
            seed_id=f'synth-{counter["n"]:04d}'
            if seed_id not in used_seed_ids:
                used_seed_ids.add(seed_id)
                return seed_id
    synthesizer=SeedSynthesizer(clients['synthesis'],selector_version=config.outer_search.selector_version,
        threshold=config.outer_search.selector_threshold,record_path=recorder.run_dir/'synthesis.jsonl',id_factory=next_seed_id)
    bank=SeedBank(p['seeds'],config.outer_search.initial_seed_score)
    search=SeedSearch(config,bank,executor,synthesizer,recorder,budget=budget,
        tool_chains={c.case_id:tuple(c.raw['Attacker Tools']) for c in p['cases']})
    summary=search.run(tuple(TargetSpec(c.case_id,c.objective) for c in p['cases']),state)
    # Standalone unit files remain authoritative; search aggregates make the audit traversable.
    initialization=[]
    for path in sorted((recorder.run_dir/'units').rglob('initializer.json')):
        initialization.append(json.loads(path.read_text()))
    if initialization:
        aggregate=recorder.run_dir/'initialization.jsonl'
        temporary=aggregate.with_name(aggregate.name+'.tmp')
        temporary.write_text(''.join(json.dumps(row,ensure_ascii=False)+'\n' for row in initialization))
        temporary.replace(aggregate)
    interfaces,usage=saved_model_evidence(recorder.run_dir/'model-calls.jsonl')
    summary.update({'run_dir':str(recorder.run_dir),'scope_id':config.run.scope_id,'run_id':config.run.run_id,
        'selector_version':config.outer_search.selector_version,'score_update_mode':config.outer_search.score_update_mode,
        'models':metadata['models'],'interface_calls':interfaces,'usage_records':usage})
    recorder.finish(summary)
    # Public stdout has only metadata and aggregate evidence, never seed/payload/body fields.
    public={k:v for k,v in summary.items() if k not in ('targets','usage_records','seed_scores','models')}
    return public, 1 if (summary['infra_failed'] or summary['method_failed'] or summary['censored']
                         or summary.get('infrastructure_cleanup_failure')) else 0
