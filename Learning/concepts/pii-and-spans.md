# PII detection, spans and replacement

Detection identifies candidate character ranges and entity categories. Redaction changes those ranges. Neither operation guarantees that all identifying information is gone: unrecognized names, context, relationships or unsupported categories may identify someone.

Original-text offsets matter. Unicode normalization can change text length; replacing a normalized offset in the original string can leave sensitive characters behind. This plan detects PII on original text and uses a separate normalized view only for injection inspection. For overlapping findings, replace the union of affected original ranges with a deterministic category label chosen by declared precedence; never concatenate unredacted fragments between overlaps. The LLD proposes CREDIT_CARD, EMAIL_ADDRESS, PHONE_NUMBER, PERSON precedence; freeze it with golden tests in phase 02.

Exercise: annotate a synthetic accented name, overlapping email/name finding and adjacent entities; write the desired replacement before implementing. Explain why category labels remove identity linkage across requests, while a stable reversible mapping would require a new retention and access-control design.
