# AVE Model Evaluation Pack

This pack pins one model version to a fixed malicious sample set, a known false-positive set, a threshold curve, and a manifest.

Release gate:

1. Fill `model_manifest.example.json` with the exact static and behavior model versions.
2. Run the fixed samples and false-positive set through the same AVE build that ships to endpoints.
3. Update `threshold_curve.csv` and the manifest metrics.
4. Attach the manifest hash to the server rollout policy so endpoints can report `static_model_version` and `behavior_model_version` against an audited evaluation package.
