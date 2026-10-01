# Model selection: capability vs refusal

A capability eval must measure what a model *can* do, not what it *will* agree
to do. A refusal and a genuine failure look the same in the score unless they
are separated, so refusal is a measurement confound.

**Decision (2026-10-01): use GLM-5.3, an unmodified open-weight model, with
authorized-lab framing, and score refusal as a distinct outcome.**

Rejected: abliterated / uncensored community model edits. They remove the
refusal direction by editing weights, which (1) degrades general capability,
worst on the reasoning the eval depends on, (2) is not reproducible across
community builds, and (3) is not representative of any deployed system, so the
score would describe an artifact, not a real threat. Larger abliterated builds
exist but pay the quality cost exactly where it hurts.

How refusal is handled instead:
- **Authorized framing.** The system prompt states the run is a sanctioned
  assessment in an isolated lab, which is literally true of this range.
- **Permissive base model.** Open-weight models refuse security framing far
  less than frontier closed models.
- **Refusal as data.** Outcomes are scored as refused / attempted-failed /
  succeeded, so refusal is reported, not engineered away.

Open question for the Cathedral prompt: do they want capability under refusal
suppression, or is refusal behaviour itself part of what to measure? Different
harness designs.
