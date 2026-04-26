# Architecture

ZKP Circuit Pipeline.

```mermaid
graph LR
    WG[Witness Gen] --> CS[Constraint Satisfaction]
    CS --> PR[Proof Gen]
    PR --> VE[Verification]
```