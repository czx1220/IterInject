"""Metadata-only strategy registry with explicit, hash-checked execution bindings."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from copy import deepcopy
from iterinject.core.search_types import SearchSeed
from iterinject.core.types import ExecutionFailure
from iterinject.models import ModelCallError


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()


class SeedCatalog:
    def __init__(self, path):
        self.path=Path(path).expanduser().resolve(strict=True)
        value=json.loads(self.path.read_text())
        allowed={'schema_version','catalog_id','created_at','scope','payload_text_included','asset_root','identity_rule','body_equivalence_verified','counts','sources','baseline','strategies'}
        if not isinstance(value,dict) or set(value)-allowed or value.get('payload_text_included') is not False:
            raise ValueError('invalid strategy catalog fields')
        if value.get('schema_version')!='2.0' or value.get('asset_root')!='iterinject.assets':
            raise ValueError('catalog requires bundled package assets')
        self.value=value
        self.strategies=tuple(value['strategies'])
        self.sources=deepcopy(value['sources'])
        self.variants={}
        strategy_ids=set()
        for entry in (*self.strategies,value['baseline']):
            if set(entry)!={'strategy_id','display_name','kind','variants'} or entry['strategy_id'] in strategy_ids:
                raise ValueError('invalid or duplicate strategy identity')
            strategy_ids.add(entry['strategy_id'])
            for variant in entry['variants']:
                if set(variant)-{'variant_id','source','source_ref','initializer_ref','generated_payload_ref'}:
                    raise ValueError('unknown source variant fields')
                identity=variant['variant_id']
                if identity in self.variants or variant['source'] not in ('injecagent','claude'):
                    raise ValueError('invalid or duplicate variant identity')
                self.variants[identity]={**deepcopy(variant),'strategy_id':entry['strategy_id'],'kind':entry['kind']}
        if value['baseline']['strategy_id']!='plain':
            raise ValueError('catalog requires the supported plain baseline identity')
        target_bound_count=0
        for variant in self.variants.values():
            reference=variant.get('generated_payload_ref')
            if reference is None:
                continue
            count=reference.get('target_count') if isinstance(reference,dict) else None
            if type(count) is not int or count<0:
                raise ValueError('catalog generated payload target_count must be a nonnegative integer')
            if variant['source']=='claude':
                target_bound_count+=count
        actual_counts={
            'strategies':len(self.strategies),
            'baselines':1,
            'shared_strategy_ids':sum(
                len({variant['source'] for variant in entry['variants']})>1
                for entry in self.strategies),
            'source_variants_including_baseline':len(self.variants),
            'claude_target_bound_payloads':target_bound_count,
        }
        declared_counts=value.get('counts')
        if (not isinstance(declared_counts,dict) or set(declared_counts)!=set(actual_counts)
                or any(type(count) is not int or count<0 for count in declared_counts.values())
                or declared_counts!=actual_counts):
            raise ValueError('catalog declared counts disagree')

    def variant(self, identity):
        try:
            return deepcopy(self.variants[identity])
        except KeyError:
            raise ValueError('unknown source variant') from None

    def asset_root(self):
        from ..assets import asset_root
        return asset_root()

    def legacy_root(self):
        """Compatibility alias; resolves bundled assets, never a parent checkout."""
        return self.asset_root()

    def validate_sources(self, legacy_root=None, *, asset_root=None):
        if legacy_root is not None and asset_root is not None:
            raise ValueError('supply only one explicit asset root')
        selected=asset_root if asset_root is not None else legacy_root
        root=Path(selected).resolve() if selected is not None else self.asset_root()
        for source in self.sources.values():
            path=(root/source['path']).resolve()
            if not path.is_relative_to(root) or not path.is_file():
                raise ModelCallError(ExecutionFailure('source_unavailable','Strategy source asset is unavailable.'))
            if hashlib.sha256(path.read_bytes()).hexdigest()!=source['sha256']:
                raise ModelCallError(ExecutionFailure('source_hash_mismatch','Strategy source asset hash changed.'))
        return root

    def default_bindings(self):
        result=[]
        for index,entry in enumerate(self.strategies):
            variants=entry['variants']
            variant=next((v for v in variants if v['source']=='injecagent'),variants[0])
            result.append({'seed_id':f'init-{index+1:04d}', 'variant_id':variant['variant_id'],
                           'initializer_kind':'native_wrapper' if variant['source']=='injecagent' else 'strategy_generation'})
        return result

    def seeds_from_bindings(self, bindings, *, fixture=False, validate_assets=False, legacy_root=None, asset_root=None):
        if validate_assets and not fixture:
            self.validate_sources(legacy_root,asset_root=asset_root)
        seeds=[]
        for index,binding in enumerate(bindings):
            kind=binding['initializer_kind']
            identity=binding['variant_id']
            if fixture and identity.startswith('fixture:'):
                if kind!='fixture' or not isinstance(binding.get('definition'),str) or not binding['definition'].strip():
                    raise ValueError('fixture requires explicit synthetic definition')
                definition=binding['definition']
                digest=hashlib.sha256(definition.encode()).hexdigest()
                if binding.get('definition_sha256',digest)!=digest:
                    raise ValueError('fixture definition hash mismatch')
                ref={'definition':definition,'origin':'fixture'}
                strategy=identity.split(':',1)[1]
            else:
                variant=self.variant(identity)
                strategy=variant['strategy_id']
                if kind not in ('native_wrapper','strategy_generation','target_bound_lookup'):
                    raise ValueError('unsupported initialization capability')
                if kind=='native_wrapper' and variant['source']!='injecagent':
                    raise ValueError('variant has no native wrapper capability')
                if kind=='strategy_generation' and variant['source']!='claude':
                    raise ValueError('variant has no strategy definition capability')
                if kind=='target_bound_lookup' and (variant['source']!='claude' or not binding.get('target_binding')):
                    raise ValueError('target-bound asset needs an explicit matching target')
                ref={**variant,'source_sha256':self.sources[variant['source']]['sha256']}
                if 'origin' in self.sources[variant['source']]:
                    ref['source_origin']=deepcopy(self.sources[variant['source']]['origin'])
                if kind=='target_bound_lookup':
                    mapping=binding.get('target_mapping')
                    if not isinstance(mapping,dict) or set(mapping)!={binding['target_binding']} or any(not isinstance(v,str) or not v for v in mapping.values()):
                        raise ValueError('target-bound source requires one explicit legacy target mapping')
                    ref['target_mapping']=dict(mapping)
                    ref['generated_source_sha256']=self.sources['generated_payloads']['sha256']
                    if 'origin' in self.sources['generated_payloads']:
                        ref['generated_source_origin']=deepcopy(self.sources['generated_payloads']['origin'])
                digest=canonical_hash(ref)
                if binding.get('definition_sha256',digest)!=digest:
                    raise ValueError('binding definition hash mismatch')
            seeds.append(SearchSeed(binding['seed_id'],strategy,identity,digest,kind,ref,
                                    target_binding=binding.get('target_binding'),registered_index=index))
        if len({s.seed_id for s in seeds})!=len(seeds):
            raise ValueError('duplicate executable seed identities')
        return tuple(seeds)
