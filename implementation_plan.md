# Google VRP Vulnerability Research Plan (AI Era)

The recent Google VRP blog post titled "Evolving the Android & Chrome VRPs for the AI Era" outlines significant shifts in how Google rewards vulnerability research. This plan focuses on aligning research efforts with these new priorities to maximize impact and reward potential.

## Background Context
Google has recognized that AI and automation have accelerated vulnerability discovery, especially for common bugs (like renderer arbitrary R/W or RCE). As a result, they are shifting their focus (and rewards) towards complex, "human-scale" vulnerabilities that automated tools struggle to find or exploit. They are also prioritizing concise, actionable reports with clear reproducers over long, AI-generated write-ups.

## Key Shifts in Google's Focus
1.  **AI Impact:** Less reward for things AI can easily find or explain (e.g., standard renderer RCE).
2.  **Android:** Focus on high user impact, zero-click, full chains (especially Titan M2), and Google-maintained Linux kernel components.
3.  **Chrome:** Focus on full chain browser process exploits on the latest OS/hardware, MiraclePtr bypasses, and providing concrete reproducers rather than lengthy explanations.
4.  **Reporting:** They want concise reports with a clear reproducer and, preferably, a proposed patch.

## Proposed Research Plan

Based on the blog post, the highest-value targets and methodologies are as follows:

### Phase 1: Target Selection & Prioritization

#### Android & Devices (Highest Priority: Top-Tier Rewards)
*   **Target 1: Pixel Titan M2 Chip:** The holy grail right now. Google is offering up to $1.5M for a zero-click full chain compromise with persistence on the Titan M2.
    *   *What to look for:* Vulnerabilities in the secure enclave, bootloader interactions, or trustzone components that could lead to persistent compromise without user interaction.
*   **Target 2: Google-Maintained Linux Kernel Components:** Google explicitly stated they are shifting focus to *their* maintained components rather than generic Linux kernel bugs (unless exploitability on Android is concretely proven).
    *   *What to look for:* Vulnerabilities in Android-specific kernel drivers, binder, or other core Google modifications to the kernel.
*   **Target 3: High User Impact / AI-Hard Bugs:** Focus on complex logic bugs or multi-step chains that AI struggles to reason about.
    *   *What to look for:* Complex state machine issues, cryptographic flaws in custom implementations, or intricate race conditions.

#### Chrome (High Priority)
*   **Target 1: MiraclePtr Bypasses:** A $250k bonus exists for exploiting an allocation protected by MiraclePtr.
    *   *What to look for:* Use-After-Free (UAF) vulnerabilities where MiraclePtr's protections can be circumvented (e.g., via type confusion or unmanaged pointers).
*   **Target 2: Full Chain Browser Process Exploits:** Google is offering up to $250k for full chains on the *latest* OS and hardware.
    *   *What to look for:* Escapes from the V8 sandbox or renderer sandbox that achieve arbitrary code execution in the main browser process. (Note: standard renderer RCE bonuses are being retired).
*   **Target 3: Utilizing New Infrastructure:** Google is releasing special Chrome configurations to help researchers demonstrate arbitrary R/W in privileged processes.
    *   *Action:* We must monitor the VRP FAQ for the release of these builds and utilize them for exploit development.

### Phase 2: Methodology & Execution

1.  **Avoid AI-Friendly Bugs:** We must move away from hunting for low-hanging fruit or bugs that tools like OSS-Fuzz or AI assistants easily catch. The focus must be on deep, structural vulnerabilities.
2.  **Focus on Reproductibility:** The blog post emphasizes *concrete proof*. Our exploits must be stable and easily reproducible. We should spend more time refining the exploit chain than writing the report.
3.  **Propose Patches:** For Android/Kernel bugs, providing a proposed patch is now "strongly incentivized." We need to include root cause analysis and a viable fix in our submissions.
4.  **Concise Reporting:** Reports should be bare-bones: the reproducer, the necessary artifacts, and a brief explanation of the impact. Avoid long, AI-generated prose.

### Phase 3: Deliverables

*   A prioritized list of specific target components within the Titan M2 architecture or Google-maintained kernel drivers.
*   Setup of the new Chrome research configurations (once released).
*   Development of proof-of-concept (PoC) exploits focused on full chains or MiraclePtr bypasses.
*   Drafting of concise, reproducer-first vulnerability reports with proposed patches.

## User Review Required

> [!IMPORTANT]
> The target scope here is immense. We need to decide whether to focus our initial efforts on **Android (Titan M2/Kernel)** or **Chrome (MiraclePtr/Browser Process)**. Please indicate which ecosystem you would like to prioritize first.

## Open Questions

> [!WARNING]
> Do you have access to physical Pixel devices (specifically those with Titan M2) for Android research, or should we focus primarily on Chrome which can be researched on standard hardware?

> [!NOTE]
> Are you currently tracking any specific CVEs or known vulnerability patterns that we should prioritize investigating within these new constraints?
