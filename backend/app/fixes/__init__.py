"""Fix advice for one package group: the LLM request and the checked answer.

Deterministic code decides what is vulnerable and which versions fix it
(Trivy's fixed versions). The LLM only explains. Its answer is untrusted:
a version counts as a fix only if it exactly equals one of Trivy's.
"""
