# Trust boundaries and prompt injection

A model interprets natural language instructions and data in a shared context. The same sentence can be an innocent quotation or an attack depending on origin and intent. A keyword match is evidence to apply a policy, not a universal classifier.

User input, retrieved documents and tool responses are all untrusted in this design. A trusted host chooses system instructions, principal and tool capabilities. The library checks content; the host enforces access control even when a detector misses an attack. For example, a retrieved paragraph asking to delete records cannot add a delete capability to the fixed read-only catalog tool.

Exercise: label who controls every arrow in HLD. Move the instruction into a tool response and ask whether its authority changed. Expected answer: no; phase 03 inspects that boundary and host authorization remains unchanged. Explain a bypass the detector might miss and why its impact is still bounded.
