import time
import tracemalloc
import json
import statistics
from datetime import datetime, timezone
from core.canonicalization import CIAFCanonicalization
from core.domain_binder import CIAFDomainBinder
from core.signer_envelope import Ed25519Signer, CIAFEnvelopeBuilder
from core.worm_verifier import WORMMerkleTree, CIAFVerifier

def measure_op(name, func, iterations=1000):
    times = []
    tracemalloc.start()
    for _ in range(iterations):
        t0 = time.perf_counter()
        func()
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000)  # ms
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    return {
        "mean_ms": statistics.mean(times),
        "std_dev_ms": statistics.stdev(times),
        "max_ms": max(times),
        "peak_memory_kb": peak / 1024
    }

def run_benchmark():
    iterations = 1000
    print(f"Running benchmark with {iterations} iterations...")
    
    signer = Ed25519Signer(key_id="test_key")
    public_key = signer.public_key_bytes
    binder = CIAFDomainBinder()
    builder = CIAFEnvelopeBuilder(binder=binder)
    verifier = CIAFVerifier(binder=binder)
    
    payload = {
        "agent_identity": {
            "service_identity": "planner_v3",
            "delegating_principal": "user_7781",
            "workflow_role": "drafter"
        },
        "task_id": "task_123",
        "vendor_id": "vendor_acme",
        "requested_amount_cents": 450000,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    results = {}
    
    results['canonicalization'] = measure_op(
        "canonicalization", 
        lambda: CIAFCanonicalization.canonicalize_json(payload), 
        iterations
    )
    
    results['bind_and_measure'] = measure_op(
        "bind_and_measure", 
        lambda: binder.bind_and_measure(payload, "RECEIPT"), 
        iterations
    )
    
    protected_bytes, digest = binder.bind_and_measure(payload, "RECEIPT")

    results['signing'] = measure_op(
        "signing", 
        lambda: signer.sign(protected_bytes), 
        iterations
    )
    
    sig = signer.sign(protected_bytes)

    results['signature_verification'] = measure_op(
        "signature_verification", 
        lambda: Ed25519Signer.verify(protected_bytes, sig, public_key), 
        iterations
    )

    results['full_envelope_creation'] = measure_op(
        "full_envelope_creation", 
        lambda: builder.create_evidence_record(payload, "RECEIPT", signer), 
        iterations
    )
    
    record = builder.create_evidence_record(payload, "RECEIPT", signer)

    results['full_evidence_verification'] = measure_op(
        "full_evidence_verification", 
        lambda: verifier.verify_evidence_record(record, public_key, "RECEIPT"), 
        iterations
    )

    # Merkle Tree Scaling
    # We want to measure the cost of append AT different sizes
    merkle_results = {}
    merkle = WORMMerkleTree()
    
    sizes_to_test = [100, 1000, 5000, 10000]
    current_size = 0
    
    for target_size in sizes_to_test:
        # grow tree to just before target size
        while current_size < target_size - 1:
            h = binder.bind_and_measure({"i": current_size}, "RECEIPT")[1]
            merkle.append_leaf(h)
            current_size += 1
            
        # measure the operation at target_size over a small batch
        # Wait, if we append, the tree grows. To measure the cost *at* target_size without 
        # growing it to 2x target_size, we just measure the next 10 appends and take the average.
        times = []
        for _ in range(10):
            h = binder.bind_and_measure({"i": current_size}, "RECEIPT")[1]
            t0 = time.perf_counter()
            merkle.append_leaf(h)
            t1 = time.perf_counter()
            times.append((t1 - t0) * 1000)
            current_size += 1
            
        merkle_results[f"append_at_{target_size}"] = {
            "mean_ms": statistics.mean(times)
        }
        
    results["merkle_scaling"] = merkle_results

    print("--- BENCHMARK RESULTS ---")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    run_benchmark()
