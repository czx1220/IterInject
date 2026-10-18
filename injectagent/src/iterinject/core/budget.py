"""Reserve before the SDK and settle actual request counts, including failed calls."""
from __future__ import annotations
from .types import ExecutionFailure


class RequestBudgetReached(RuntimeError):
    def __init__(self):
        self.failure=ExecutionFailure('request_budget_reached','API request budget exhausted.')
        super().__init__(self.failure.message)


class RequestBudget:
    def __init__(self, max_api_requests):
        if type(max_api_requests) is not int or max_api_requests<0:
            raise ValueError('request budget must be a nonnegative integer')
        self.max_api_requests=max_api_requests
        self.used=0
        self._reserved=0
        self.by_role={}

    @property
    def remaining(self):
        return self.max_api_requests-self.used-self._reserved

    def reserve(self):
        if self.remaining<=0:
            raise RequestBudgetReached()
        self._reserved+=1

    def settle(self, role, actual):
        self._reserved-=1
        if type(actual) is not int or actual<0:
            raise ValueError('underlying API counter must be monotonic')
        self.used+=actual
        if actual:
            self.by_role[role]=self.by_role.get(role,0)+actual
        if actual>1:
            raise RuntimeError('one completion performed more than one SDK request')

    def snapshot(self):
        return {'max_api_requests':self.max_api_requests,'used':self.used,'by_role':dict(self.by_role)}

    @classmethod
    def from_state(cls,state):
        if not isinstance(state,dict) or set(state)!={'max_api_requests','used','by_role'}:
            raise ValueError('invalid saved request budget fields')
        if not isinstance(state['by_role'],dict) or any(
                not isinstance(role,str) or not role.strip() or type(count) is not int or count<0
                for role,count in state['by_role'].items()):
            raise ValueError('saved role counters must be nonnegative integers')
        result=cls(state['max_api_requests'])
        result.used=state['used']
        result.by_role=dict(state['by_role'])
        if type(result.used) is not int or not 0<=result.used<=result.max_api_requests or sum(result.by_role.values())!=result.used:
            raise ValueError('invalid saved request budget')
        return result


class BudgetedClient:
    def __init__(self, client, budget:RequestBudget, *, role, fixture=False):
        self.client=client
        self.budget=budget
        self.role=role
        self.fixture=fixture

    def __getattr__(self,name):
        return getattr(self.client,name)

    def complete(self,messages):
        before=self.client.call_count
        if self.fixture:
            result=self.client.complete(messages)
            if self.client.call_count!=before:
                raise RuntimeError('fixture unexpectedly performed an API request')
            return result
        self.budget.reserve()
        try:
            return self.client.complete(messages)
        finally:
            self.budget.settle(self.role,self.client.call_count-before)
