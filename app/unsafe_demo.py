# INTENTIONAL BAD EXAMPLE for CI evidence (Phase 04 Step 2)
import pickle

def load_user_profile(raw_bytes):
	# Do NOT do this in the real code. This is here to trigger a Semgrep gate.
	return pickle.loads(raw_bytes)
