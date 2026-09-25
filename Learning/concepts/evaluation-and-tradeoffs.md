# Evaluation and tradeoffs

Recall asks how much labeled sensitive content was detected; precision asks how many detections were truly sensitive. A high recall achieved by redacting everything destroys utility. Report each category separately so easy email cases cannot hide missed names.

An attack detector metric is different from attack success against a model. A flagged attack can still succeed if content is released first; an unflagged attack can fail because deterministic tool permissions deny it. Measure enforcement invariants separately from model outcomes.

Exercise: in 100 positive entities, 95 detected with 10 extra false findings gives recall 95% and precision 95/105 ≈90.5%. State that small or synthetic samples limit inference. Explain why repeatedly adjusting thresholds after seeing held-out errors turns that set into development data.
