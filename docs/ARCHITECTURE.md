
# Architecture: hyperdag-core

This repository implements the ZKP circuit pipeline.

```mermaid
graph LR
    WG[Witness Gen] --> CS[Constraint Satisfaction]
    CS --> PR[Proof Gen]
    PR --> VE[Verification]
```
