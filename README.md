# IterInject

Official repository for **IterInject: Indirect Prompt Injection Against LLM Agents via Feedback-Guided Iterative Optimization**.

**Findings of EMNLP 2026**

[![arXiv](https://img.shields.io/badge/arXiv-2605.24659-b31b1b.svg)](https://arxiv.org/abs/2605.24659)
[![Code](https://img.shields.io/badge/Code-coming%20soon-orange.svg)](#code-release)

**Zixuan Chen, Jiaxiang Chen, Li Luo, Ke Xu, Xiaoxiang Huang, Tanfeng Sun, Xinghao Jiang**<br>
Shanghai Jiao Tong University · The University of Hong Kong

[Paper (arXiv)](https://arxiv.org/abs/2605.24659) · [PDF](https://arxiv.org/pdf/2605.24659) · [OpenReview](https://openreview.net/forum?id=OBXkjB2JzD)

## Code release

> **Code coming soon.** We are preparing the official implementation for release. The code will be made available in this repository soon.

This repository currently contains paper information only. Please star or watch the repository for updates.

## Overview

IterInject is a feedback-guided iterative framework for studying indirect prompt injection against LLM agents. It closes the loop between injection, diagnosis, and refinement using structured diagnostic feedback and an LLM-based optimizer conditioned on the optimization history. A synthesis step generates new disguise seeds from failure patterns.

The paper evaluates IterInject on AgentDojo and InjectAgent, extends the analysis to Claude Code, and investigates the mechanisms underlying indirect prompt injection.

## Citation

If you find this work useful, please cite our paper:

```bibtex
@misc{chen2026iterinject,
  title = {IterInject: Indirect Prompt Injection Against LLM Agents via Feedback-Guided Iterative Optimization},
  author = {Zixuan Chen and Jiaxiang Chen and Li Luo and Ke Xu and Xiaoxiang Huang and Tanfeng Sun and Xinghao Jiang},
  year = {2026},
  eprint = {2605.24659},
  archivePrefix = {arXiv},
  primaryClass = {cs.LG},
  url = {https://arxiv.org/abs/2605.24659}
}
```
