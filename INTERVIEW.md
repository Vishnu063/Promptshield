# PromptShield security gateway prototype: reviewer guide

Python gateway code with injection/PII detectors, rate limiting, tests, Docker, Kubernetes, and Terraform material.

## Start the review

Explain the detection limits and false positives, token-bucket behavior, and how gateway tests differ from a deployed security guarantee.

| Source | Review focus |\n| --- | --- |\n| [Dockerfile](Dockerfile) | Build context, runtime configuration, ports, and persistence |\n| [docker-compose.yml](docker-compose.yml) | Build context, runtime configuration, ports, and persistence |\n| [.github/workflows/ci.yml](.github/workflows/ci.yml) | Triggers, credentials, failure handling, and deploy conditions |\n| [k8s/deployment.yaml](k8s/deployment.yaml) | Implementation, assumptions, and operational boundaries |\n| [k8s/network-policy.yaml](k8s/network-policy.yaml) | Implementation, assumptions, and operational boundaries |\n| [terraform/main.tf](terraform/main.tf) | Inputs, state, permissions, cost, and resource lifecycle |

## A useful interview walkthrough

1. State the problem and the specific part you implemented or changed.
2. Open the source above and follow one request, release, or failure from start to finish.
3. Show a reproducible result, including an actual failure and the observation that confirms recovery.
4. Explain one tradeoff and one limitation. Distinguish a local test from a live deployment.

## Evidence and limits

This guide is based on the default-branch source inspected on 16 October 2026. It is a source review, not a fresh deployment or a certification of every feature. Existing CI runs and tests should be checked at the commit being demonstrated. Do not present screenshots, inherited code, planned features, or old README statements as proof of a current deployment.
