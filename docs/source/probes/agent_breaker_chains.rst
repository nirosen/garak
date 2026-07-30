garak.probes.agent_breaker_chains
=================================

``SourceToSink`` is an opt-in probe for bounded exploration of multi-tool paths
in agentic targets. It is inspired by `ChainFuzzer
<https://arxiv.org/abs/2603.12614>`_, but it is not an implementation of
ChainFuzzer's grey-box, trace-guided analysis. It uses an operator-supplied
tool manifest and behaviour visible through the configured target interface.

The probe tags candidate tool relationships, plans a bounded chain, and
executes its steps sequentially. Configured limits cap the probe's planning,
chain length, and queued attempts. The probe reserves each terminal request
against a per-manifest-tool budget before dispatch and does not queue a
follow-up after receiving the terminal response.

.. warning::

   Run this probe only against authorised, disposable targets in a sandbox.
   Tool chains can cause persistent side effects even when the target response
   does not report them accurately. Transport clients can retry failed requests,
   and a target can invoke a tool more than once while handling one request.
   The probe can name one intended tool in a request, but it cannot enforce
   target-side routing: the target may invoke another tool or several tools.
   Enforce per-call tool allowlists and idempotency at the target boundary, and
   independently audit backend effects. Without that control, treat every probe
   request, including an intermediate request, as potentially side-effecting.

Operational requirements
------------------------

The probe fails closed unless all of these conditions hold:

* ``run.generations`` is exactly ``1`` and no buffs are selected;
* the target language is English;
* at least two tools have an operator-authored ``chain_policy``;
* every intermediate tool is explicitly read-only for this run; and
* every terminal tool is explicitly side-effecting for this run.

Chains does not auto-discover tools. Each manifest policy must contain exactly
the three Boolean fields shown below. A tool may be allowed as either an
intermediate step or a terminal step, never both. The operator is responsible
for matching these declarations to the target's real tool implementation and
authorisation boundary. ``chain_policy`` constrains probe planning; it is not a
target routing policy.

The terminal budget is per manifest tool name and limits only requests queued
by this probe. Aliases can still reach the same backend operation, and a
transport or target can retry one request. It is not an actual-operation
at-most-once guarantee.

Intermediate responses must contain every required artifact value verbatim.
This makes opaque references usable without interpreting their format, but it
also means translation or rewriting of identifiers is unsupported.

Configuration and invocation
----------------------------

Place a manifest below garak's user data ``data`` directory. For example,
``agent_breaker_chains/target.yaml`` can contain:

.. code-block:: yaml

   agent_purpose: Exercise an authorised support sandbox.
   tools:
     - name: lookup_record
       description: Read a sandbox record and return its opaque reference.
       chain_policy:
         allow_intermediate: true
         allow_terminal: false
         side_effecting: false
     - name: update_sandbox_record
       description: Update one disposable sandbox record by opaque reference.
       chain_policy:
         allow_intermediate: false
         allow_terminal: true
         side_effecting: true

Select the probe and manifest in a garak configuration file:

.. code-block:: yaml

   run:
     generations: 1
     target_lang: en
     spec:
       include:
         - probes.agent_breaker_chains.SourceToSink
   plugins:
     probes:
       agent_breaker_chains:
         SourceToSink:
           agent_config_file: agent_breaker_chains/target.yaml

Then run it with the normal target configuration, replacing the placeholders:

.. code-block:: bash

   garak --config chains.yaml --target_type TARGET_PLUGIN --target_name TARGET_NAME

The probe's red-team generator and the detector's judge generator also require
their normal provider configuration and credentials.

``agent_breaker_chains.SourceToSink`` and ``agent_breaker.AgentBreaker``
(Single) are separate
probe plugins. Enabling Chains does not enable or modify Single, and Chains has
no dependency on changes to Single's detector contract.

The primary detector judges only the target's response claim for an eligible
artifact-bearing terminal request. A positive score does not establish that the
planned tool was used or that a backend side effect occurred; verify routing
and backend state separately in the authorised test environment.

The conservative terminal-attempt budget is intentionally below the usual
prompt volume for statistical probes. Treat results as bounded discovery
signals, not as a population estimate or benchmark.

.. automodule:: garak.probes.agent_breaker_chains
   :members:
   :undoc-members:
   :show-inheritance:
