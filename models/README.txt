AVE ONNX models directory (next to edr_agent.exe after install).

Release installers copy from ../onnx-output/*.onnx into this folder before packaging (see
scripts/sync_onnx_output_to_models.sh). For local builds, run that script or place .onnx
here directly (e.g. static.onnx, behavior.onnx). See agent.toml.example [ave] model_dir
and docs/AVE_ONNX_LOCAL_STACK.md.
