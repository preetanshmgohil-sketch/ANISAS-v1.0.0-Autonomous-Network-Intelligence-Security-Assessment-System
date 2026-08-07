Deployment guidance: resource limits and safe runtime

Container and Kubernetes guidance

- Always set resource requests and limits for CPU and memory to avoid noisy-neighbor and DoS conditions.

Kubernetes example (deployment snippet):

apiVersion: apps/v1
kind: Deployment
metadata:
  name: anisas
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: anisas
          image: ghcr.io/owner/anisas:latest
          resources:
            requests:
              cpu: "250m"
              memory: "512Mi"
            limits:
              cpu: "1000m"
              memory: "2Gi"
          env:
            - name: ANISAS_INFERENCE_TIMEOUT
              value: "5"
            - name: ANISAS_MAX_THREADS
              value: "1"

Docker run example (host-level limits):

  docker run --rm --cpus="1.0" --memory="1g" ghcr.io/owner/anisas:latest

Runtime safeguards in code

- The codebase uses ANISAS_INFERENCE_TIMEOUT and ANISAS_MAX_THREADS to constrain model inference. Configure these via environment variables in container runtime.
- Ensure host-level cgroup limits are applied for untrusted environments.

Operational notes

- Enforce timeouts on long-running tasks and run heavy workloads in batch jobs with quotas.
- Monitor process memory usage and terminate and restart workers that exceed thresholds.
