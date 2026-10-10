"""Sequential, bounded outer search with atomic target-level scoring."""
from __future__ import annotations
from dataclasses import asdict
from .budget import RequestBudget
from .search_records import InfrastructureCleanupError
from .search_types import SearchConfiguration
from .seed_bank import trial_mean
from .references import ReferencePool, render
from .types import ExecutionFailure,FeedbackStatus,TargetSpec
from .logging import serialize
from ..seeds.synthesis import select_operation,to_selector_trajectories


class NullRecorder:
    def __init__(self): self.events=[]; self.commits=[]
    def event(self,kind,fields): self.events.append({'kind':kind,**serialize(fields)})
    def commit_target(self,result,state): self.commits.append((serialize(result),serialize(state)))


def has_success(trial):
    return (trial.failure is None and trial.optimization is not None and
            any(a.result.feedback is not None and a.result.feedback.status==FeedbackStatus.SUCCESS
                for a in trial.optimization.attempts))


def failure_category(failure, trial=None):
    if failure.kind=='request_budget_reached': return 'censored'
    if failure.kind in {'initializer_invalid_output','invalid_initializer_output','invalid_synthesis_output',
                         'invalid_optimizer_output','optimizer_empty_output','empty_model_response','invalid_model_response'}:
        return 'method_failed'
    if failure.kind=='parse_error' and trial and trial.optimization:
        for attempt in trial.optimization.attempts:
            for stage in attempt.result.trace.data.get('stages',[]):
                raw=stage.get('raw_eval')
                if isinstance(raw,dict) and raw.get('eval')=='invalid':
                    return 'method_failed'
    return 'infra_failed'


def summarize_targets(planned, rows, scores, budget):
    counts={k:sum(r['status']==k for r in rows) for k in ('completed','method_failed','infra_failed','censored')}
    unstarted=planned-len(rows)
    successes=sum(r['success'] for r in rows)
    observed=counts['completed']+counts['method_failed']
    valid=sum(r['status']=='completed' and r.get('scored_trials',0)>0 for r in rows)
    ratio=lambda numerator,denominator: numerator/denominator if denominator else None
    return {'planned':planned,'started':len(rows),**counts,'unstarted':unstarted,'successes':successes,
            'observed_denominator':observed,'valid_denominator':valid,
            'ASR_observed':ratio(successes,observed),'ASR_valid':ratio(successes,valid),
            'coverage':ratio(observed,planned),'confirmed_success_fraction_planned':ratio(successes,planned),
            'invalid_targets':sum(r.get('failure',{}).get('kind')=='parse_error' and r['status']=='method_failed' for r in rows),
            'seed_trials':sum(len(r['trials']) for r in rows),
            'synthesis_interface_calls':sum(r.get('synthesis_interface_calls',0) for r in rows),
            'api_requests':budget.used,'api_calls':{role:budget.by_role.get(role,0) for role in ('victim','optimizer','simulation','initializer','synthesis')},
            'seed_scores':scores,'targets':rows}


class SeedSearch:
    def __init__(self, config:SearchConfiguration, seed_bank, executor, synthesizer, recorder,
                 *, reference_pool=None, budget=None, tool_chains=None):
        self.config=config; self.seed_bank=seed_bank; self.executor=executor
        self.synthesizer=synthesizer; self.recorder=recorder
        self.references=reference_pool if reference_pool is not None else ReferencePool()
        self.budget=budget if budget is not None else RequestBudget(config.run.max_api_requests)
        self.tool_chains=tool_chains or {}
        self.rows=[]; self.generated_count=0
        self.infrastructure_cleanup_failure=None

    def state(self,next_target_index):
        return {'next_target_index':next_target_index,'seed_bank':self.seed_bank.snapshot(),
                'references':self.references.snapshot(),'budget':self.budget.snapshot(),
                'generated_count':self.generated_count,'targets':serialize(self.rows)}

    def restore(self,state):
        bank=self.seed_bank.from_state(state['seed_bank'])
        references=ReferencePool.from_state(state['references'])
        saved=RequestBudget.from_state(state['budget'])
        if saved.max_api_requests!=self.budget.max_api_requests:
            raise ValueError('resume request budget changed')
        rows=state['targets']
        generated=state['generated_count']
        if not isinstance(rows,list) or type(generated) is not int or not 0<=generated<=self.config.outer_search.max_generated_seeds:
            raise ValueError('invalid search resume state')
        self.seed_bank=bank;self.references=references
        # Existing BudgetedClient wrappers retain the same budget instance.
        self.budget.used=saved.used; self.budget.by_role=saved.by_role
        self.rows=list(rows);self.generated_count=generated
        self.infrastructure_cleanup_failure=None

    def run(self,targets:tuple[TargetSpec,...],resume_state=None):
        if len({t.target_id for t in targets})!=len(targets):
            raise ValueError('duplicate search target identities')
        start=0
        if resume_state is not None:
            if not isinstance(resume_state,dict):
                raise ValueError('invalid search resume state')
            start=resume_state.get('next_target_index')
            rows=resume_state.get('targets')
            if (type(start) is not int or not 0<=start<=len(targets)
                    or not isinstance(rows,list) or any(not isinstance(r,dict) for r in rows)
                    or [r.get('target_id') for r in rows]!=[t.target_id for t in targets[:start]]):
                raise ValueError('resume target manifest mismatch')
            self.restore(resume_state)
        for index,target in enumerate(targets[start:],start):
            working=self.seed_bank.clone(); references=self.references.clone()
            means={};tried=set();trials=[];new_ids=[];syntheses=0
            failure=None;failed_trial=None;success=False;stop_reason='seed_exhausted'
            def execute(seed,reason):
                nonlocal failure,failed_trial,success
                selected=references.select(scope_id=self.config.run.scope_id,
                    tool_chain_signature=self.tool_chains.get(target.target_id,()),max_references=self.config.outer_search.max_references)
                rendered=tuple(render(ref) for ref in selected)
                self.recorder.event('seed_selected',{'target_id':target.target_id,'seed_id':seed.seed_id,
                    'selection_reason':reason,'score':working.scores[seed.seed_id],
                    'references':[{'reference_id':r.reference_id,'payload_sha256':r.payload_sha256,'source':r.source} for r in selected]})
                trial=self.executor.execute(target,seed,rendered)
                if trial.target_id!=target.target_id or trial.seed_id!=seed.seed_id:
                    raise ValueError('executor returned mismatched trial identities')
                trials.append(trial);tried.add(seed.seed_id)
                self.recorder.event('trial_finished',{'trial_id':trial.trial_id,'seed_id':seed.seed_id,
                    'target_id':target.target_id,'run_dir':trial.run_dir,'api_calls':trial.api_calls,'failure':trial.failure})
                if trial.failure:
                    failure=trial.failure;failed_trial=trial;return trial
                mean=trial_mean(trial)
                if mean is None:
                    raise ValueError('complete trial has no valid feedback')
                means[seed.seed_id]=mean;success=has_success(trial)
                self.recorder.event('trial_mean',{'target_id':target.target_id,'seed_id':seed.seed_id,'q':mean})
                return trial
            try:
                self.recorder.event('target_started',{'target_id':target.target_id,'target_index':index,'entering_scores':working.scores})
                while not success and not failure and len(trials)<self.config.outer_search.max_seed_trials_per_target:
                    batch=working.rank_untried(target,tried,min(self.config.outer_search.top_k,self.config.outer_search.max_seed_trials_per_target-len(trials)))
                    if not batch:break
                    batch_trials=[]
                    for seed in batch:
                        batch_trials.append(execute(seed,'stable_top_k'))
                        if success or failure:break
                    if success or failure:break
                    if (batch_trials and syntheses<self.config.outer_search.max_syntheses_per_target
                            and self.generated_count+len(new_ids)<self.config.outer_search.max_generated_seeds):
                        operation=select_operation(to_selector_trajectories(tuple(batch_trials)),
                            self.config.outer_search.selector_threshold,self.config.outer_search.selector_version)
                        parents=tuple(t.seed_id for t in batch_trials)
                        self.recorder.event('synthesis_started',{'target_id':target.target_id,'operation':operation,
                            'selector_version':self.config.outer_search.selector_version,'parents':parents})
                        syntheses+=1
                        candidate=self.synthesizer.synthesize(target,tuple(batch_trials),operation,parents)
                        fingerprint=lambda s:(s.definition_sha256,s.initializer_kind,s.target_binding)
                        duplicate=any(fingerprint(candidate)==fingerprint(s) for s in working.eligible(target))
                        self.recorder.event('candidate_generated',{'target_id':target.target_id,'seed_id':candidate.seed_id,
                            'definition_sha256':candidate.definition_sha256,'parents':candidate.parent_seed_ids,
                            'rejected_duplicate':duplicate,'candidate':serialize(candidate)})
                        if not duplicate:
                            if candidate.target_binding is not None or candidate.initializer_kind not in ('strategy_generation','fixture'):
                                raise ValueError('synthesized candidate is not a reusable strategy')
                            provisional=sum(means.values())/len(means)
                            working.register(candidate,provisional);new_ids.append(candidate.seed_id)
                            self.recorder.event('provisional_registration_score',{'target_id':target.target_id,'seed_id':candidate.seed_id,'score':provisional})
                            if len(trials)<self.config.outer_search.max_seed_trials_per_target:
                                execute(working.get(candidate.seed_id),'generated_next_once_v1')
                if success:stop_reason='success'
                elif failure:stop_reason='global_budget' if failure.kind=='request_budget_reached' else failure.kind
                elif len(trials)>=self.config.outer_search.max_seed_trials_per_target:stop_reason='target_trial_limit'
                if not failure and not means:
                    # No valid completed search outcome exists when the configured local bound is zero.
                    failure=ExecutionFailure('no_scored_trial','Target has no completed scored trial.')
                    stop_reason=failure.kind
            except Exception as exc:
                reported=getattr(exc,'failure',None)
                failure=reported if isinstance(reported,ExecutionFailure) else ExecutionFailure(
                    'persistence_error' if isinstance(exc,OSError) else 'search_execution_error',
                    'Search operation failed; prior durable evidence retained.')
                stop_reason='global_budget' if failure.kind=='request_budget_reached' else failure.kind
            status=failure_category(failure,failed_trial) if failure else 'completed'
            row={'target_id':target.target_id,'target_index':index,'status':status,'success':success and not failure,
                 'stop_reason':stop_reason,'scored_trials':len(means),'trials':[{'trial_id':t.trial_id,'seed_id':t.seed_id,'run_dir':t.run_dir,
                    'api_calls':t.api_calls,'interface_calls':t.interface_calls,'q':trial_mean(t),'failure':serialize(t.failure)} for t in trials],
                 'synthesis_interface_calls':syntheses,'generated_seed_ids':new_ids if not failure else [],
                 'failure':asdict(failure) if failure else {},'score_committed':False}
            if not failure:
                try:
                    before=self.seed_bank.scores
                    eligible=tuple(s.seed_id for s in working.eligible(target))
                    working.apply_target(eligible,means,tuple(new_ids))
                    references.add_successes(target,tuple(trials),scope_id=self.config.run.scope_id,
                        tool_chain_signature=self.tool_chains.get(target.target_id,()),target_commit_index=index)
                    committed_row={**row,'score_committed':True}
                    pending_rows=[*self.rows,committed_row]
                    state={'next_target_index':index+1,'seed_bank':working.snapshot(),'references':references.snapshot(),
                           'budget':self.budget.snapshot(),'generated_count':self.generated_count+len(new_ids),'targets':serialize(pending_rows)}
                    try:
                        self.recorder.commit_target(committed_row,state)
                    except InfrastructureCleanupError as exc:
                        # The recorder crossed its durable checkpoint commit point.
                        self.infrastructure_cleanup_failure=asdict(exc.failure)
                except Exception:
                    failure=ExecutionFailure('persistence_error','Target commit failed before publication; prior state retained.')
                    status='infra_failed'
                    row.update(status=status,success=False,stop_reason=failure.kind,
                               generated_seed_ids=[],failure=asdict(failure),score_committed=False)
                else:
                    self.seed_bank=working;self.references=references;self.generated_count+=len(new_ids)
                    row=committed_row
                    if self.infrastructure_cleanup_failure is None:
                        try:
                            self.recorder.event('score_commit',{'target_id':target.target_id,'before':before,'after':working.scores,'tried_means':means,'new_seed_ids':new_ids})
                        except Exception:
                            self.infrastructure_cleanup_failure=asdict(InfrastructureCleanupError().failure)
            if failure:
                try:
                    self.recorder.event('target_aborted',row)
                    if hasattr(self.recorder,'record_aborted'):self.recorder.record_aborted(row)
                except Exception:
                    failure=ExecutionFailure('persistence_error','Aborted target evidence could not be persisted; search stopped.')
                    status='infra_failed'
                    row.update(status=status,success=False,stop_reason=failure.kind,failure=asdict(failure))
            self.rows.append(row)
            if status in ('censored','infra_failed') or self.infrastructure_cleanup_failure:break
        summary=summarize_targets(len(targets),self.rows,self.seed_bank.scores,self.budget)
        summary['infrastructure_cleanup_failure']=self.infrastructure_cleanup_failure
        return summary
