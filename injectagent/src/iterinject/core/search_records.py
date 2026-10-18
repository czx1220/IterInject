"""Durable search events and checkpoints; incomplete targets are never replayed."""
from __future__ import annotations
import json
import os
import re
from pathlib import Path
from .logging import _append_record,_write_new,_check_public_metadata,serialize
from .types import ExecutionFailure


class InfrastructureCleanupError(RuntimeError):
    """The checkpoint is committed; only subsequent bookkeeping failed."""

    def __init__(self):
        self.failure = ExecutionFailure(
            'infrastructure_cleanup_failure',
            'Target checkpoint committed, but subsequent infrastructure cleanup failed.')
        super().__init__(self.failure.message)


def _sync_directory(path):
    descriptor=os.open(path,os.O_RDONLY | getattr(os,'O_DIRECTORY',0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _clear_active_marker(path):
    path.unlink(missing_ok=True)
    _sync_directory(path.parent)


def atomic_json(path,value):
    path=Path(path)
    temporary=path.with_name(path.name+'.tmp')
    encoded=json.dumps(serialize(value),ensure_ascii=False,allow_nan=False)+'\n'
    with temporary.open('w',encoding='utf-8') as stream:
        stream.write(encoded);stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)
    _sync_directory(path.parent)


def _checkpoint_covers_marker(state, marker):
    if not isinstance(state, dict) or not isinstance(marker, dict):
        return False
    index=marker.get('target_index')
    next_index=state.get('next_target_index')
    rows=state.get('targets')
    if (type(index) is not int or index<0 or type(next_index) is not int
            or next_index<=index or not isinstance(rows,list) or len(rows)!=next_index):
        return False
    row=rows[index]
    return (isinstance(row,dict) and type(row.get('target_index')) is int
            and row.get('target_index')==index
            and row.get('target_id')==marker.get('target_id')
            and isinstance(row.get('target_id'),str) and bool(row['target_id'])
            and row.get('status')=='completed' and row.get('score_committed') is True)


class FileSearchRecorder:
    def __init__(self,run_dir,metadata,*,resume=False):
        self.run_dir=Path(run_dir).expanduser().resolve()
        _check_public_metadata(serialize(metadata))
        json.dumps(serialize(metadata),allow_nan=False)
        if resume:
            if not self.run_dir.is_dir():raise ValueError('resume search is unavailable')
            saved=json.loads((self.run_dir/'search.json').read_text())
            if saved['identity']!=metadata['identity']:
                raise ValueError('resume source/config/manifest hashes changed')
            if not (self.run_dir/'checkpoint.json').exists():
                raise ValueError('interrupted_target: no complete target checkpoint')
            marker_path=self.run_dir/'active_target.json'
            if marker_path.exists():
                try:
                    marker=json.loads(marker_path.read_text())
                    state=json.loads((self.run_dir/'checkpoint.json').read_text())
                except (OSError,ValueError):
                    raise ValueError('interrupted_target: completion cannot be established') from None
                if not _checkpoint_covers_marker(state,marker):
                    raise ValueError('interrupted_target: uncommitted target cannot be replayed')
                _clear_active_marker(marker_path)
        else:
            self.run_dir.mkdir(parents=True,exist_ok=False,mode=0o700)
            _write_new(self.run_dir/'search.json',metadata)
            for name in ('events.jsonl','targets.jsonl','initialization.jsonl','synthesis.jsonl'):
                (self.run_dir/name).touch(exist_ok=False)
            (self.run_dir/'generated-seeds').mkdir()
            _sync_directory(self.run_dir)
            _sync_directory(self.run_dir.parent)
        self.events_path=self.run_dir/'events.jsonl'

    def event(self,kind,fields):
        if kind=='target_started':
            atomic_json(self.run_dir/'active_target.json',{'target_id':fields['target_id'],'target_index':fields['target_index']})
        if kind=='candidate_generated' and 'candidate' in fields:
            seed_id=fields.get('seed_id')
            if not isinstance(seed_id,str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}',seed_id) is None:
                raise ValueError('candidate seed identity must be a safe basename')
            candidate=fields['candidate']
            if not isinstance(candidate,dict) or candidate.get('seed_id')!=seed_id:
                raise ValueError('candidate identity does not match the event')
            path=self.run_dir/'generated-seeds'/f'{seed_id}.json'
            serialized=serialize(candidate)
            if path.exists() and json.loads(path.read_text())!=serialized:
                raise ValueError('candidate identity conflicts with persisted evidence')
            atomic_json(path,serialized)
        _append_record(self.events_path,{'kind':kind,**fields})

    def commit_target(self,target_result,state):
        # The checkpoint is authoritative; no committed-looking side record may
        # precede this durable publication point.
        atomic_json(self.run_dir/'checkpoint.json',state)
        try:
            _append_record(self.run_dir/'targets.jsonl',target_result)
            _clear_active_marker(self.run_dir/'active_target.json')
            self.event('target_committed',{'target_id':target_result['target_id'],'next_target_index':state['next_target_index']})
        except Exception:
            raise InfrastructureCleanupError() from None

    def record_aborted(self,row):
        _append_record(self.run_dir/'targets.jsonl',row)

    def checkpoint(self):
        return json.loads((self.run_dir/'checkpoint.json').read_text())

    def finish(self,summary):
        atomic_json(self.run_dir/'summary.json',summary)
