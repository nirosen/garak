garak.detectors.agent_breaker_chains
====================================

The AgentBreaker Chains detector is a terminal-only, V6-derived
model-as-judge detector. It evaluates whether a target's response gives
concrete evidence for a mutating effect requested or implied by an eligible,
artifact-bearing terminal request.

The judge receives only the exact terminal attack prompt and corresponding
target response. It does not receive tool definitions, intermediate artifacts,
the chain transcript, planner state, experiment labels, or target-provided
backend metadata. ``YES`` scores as a hit; ``NO`` and ``UNKNOWN`` score as a
pass. Ineligible or unevaluable outputs are not scored.

This detector scores response claims, not backend truth. A hit must not be
reported as proof that an external state change occurred. Use independent
backend observations when validating an authorised, disposable sandbox target.
The detector also cannot verify that the target routed the request to the
manifest tool named by the probe.
Scores are also dependent on the configured judge model. Preserving the V6
prompt text does not establish accuracy on new target or effect families;
validate the chosen judge on held-out responses before interpreting results.

This detector is used by the separate opt-in ``SourceToSink`` probe. It
does not replace the detector used by ``agent_breaker.AgentBreaker`` (Single)
and does not depend on changes to Single's detector contract.

.. automodule:: garak.detectors.agent_breaker_chains
   :members:
   :undoc-members:
   :show-inheritance:
