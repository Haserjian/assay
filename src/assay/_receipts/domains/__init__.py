"""Receipt domain namespaces."""

__all__ = [
    "mlb",
    "governance",
    "markets",
    "deprecated",
    "permission",
    "value",
    "integrity",
    "sigil",
    "actuator_v2",
    "alerts",
    "sensory",
    "perception_session",
    "policy_experiment",
    "kill_switch",
    "blockages",
    "model_call",
    "capability_use",
    "guardian_verdict",
    "dignity_budget",
]

# Optional exports
try:
    from .permission import PermissionReceipt  # noqa: F401
except Exception:
    PermissionReceipt = None

try:
    from .governance import PolicyUpdateReceipt  # noqa: F401
except Exception:
    PolicyUpdateReceipt = None

try:
    from .integrity import IntegrityCheckReceipt  # noqa: F401
except Exception:
    IntegrityCheckReceipt = None

try:
    from .organism_state import OrganismStateTransitionReceipt, OrganismState  # noqa: F401
except Exception:
    OrganismStateTransitionReceipt = None
    OrganismState = None

try:
    from .sigil import SigilExecutionReceipt, ContextFrameReceipt  # noqa: F401
except Exception:
    SigilExecutionReceipt = None
    ContextFrameReceipt = None

try:
    from .alerts import AlertReceipt  # noqa: F401
except Exception:
    AlertReceipt = None

# Sensory receipts (Phase I Embodiment)
try:
    from .sensory import (  # noqa: F401
        VisionObservationReceipt,
        VoiceObservationReceipt,
        PerceptReceipt,
        PerceptionMembraneReceipt,
        SensoryModality,
        VisionCaptureMode,
        VoiceCaptureMode,
        ConsentLevel,
        MembraneVerdict,
    )
except Exception:
    VisionObservationReceipt = None
    VoiceObservationReceipt = None
    PerceptReceipt = None
    PerceptionMembraneReceipt = None
    SensoryModality = None
    VisionCaptureMode = None
    VoiceCaptureMode = None
    ConsentLevel = None
    MembraneVerdict = None

# Perception Session receipts (Phase I Embodiment - Container Contract)
try:
    from .perception_session import (  # noqa: F401
        PerceptionSessionReceipt,
        SensoriumReceipt,
        VideoSensorReceipt,
        SessionState,
        SensorType,
        SessionPurpose,
        TrustProfile,
        ConsentMethod,
        KillSwitchType,
        ConsentProof,
        SessionScope,
        KillSwitch,
        SessionTransition,
        DetectedElement,
        VLMDetection,
        VoiceIntentSnapshot,
        KeyframeData,
        TemporalEvent,
        create_perception_session,
        create_sensorium_snapshot,
    )
except Exception:
    PerceptionSessionReceipt = None
    SensoriumReceipt = None
    VideoSensorReceipt = None
    SessionState = None
    SensorType = None
    SessionPurpose = None
    TrustProfile = None
    ConsentMethod = None
    KillSwitchType = None
    ConsentProof = None
    SessionScope = None
    KillSwitch = None
    SessionTransition = None
    DetectedElement = None
    VLMDetection = None
    VoiceIntentSnapshot = None
    KeyframeData = None
    TemporalEvent = None
    create_perception_session = None
    create_sensorium_snapshot = None

# Horizon receipts (world model)
try:
    from .horizon import (  # noqa: F401
        PredictionReceipt,
        SurpriseReceipt,
        WorldHypothesisReceipt,
    )
except Exception:
    PredictionReceipt = None
    SurpriseReceipt = None
    WorldHypothesisReceipt = None

# Policy experiment receipts (Quintet policy evolution)
try:
    from .policy_experiment import (  # noqa: F401
        PolicyExperimentReceipt,
        ExperimentMetrics,
        create_experiment_receipt,
        compute_evidence_hash,
    )
except Exception:
    PolicyExperimentReceipt = None
    ExperimentMetrics = None
    create_experiment_receipt = None
    compute_evidence_hash = None

# Capability receipts (Receipt Internet v0)
try:
    from .capability import (  # noqa: F401
        CapabilityReceipt,
        CapabilityScope,
        CapabilityConstraints,
        create_capability_receipt,
        compute_capability_id,
    )
except Exception:
    CapabilityReceipt = None
    CapabilityScope = None
    CapabilityConstraints = None
    create_capability_receipt = None
    compute_capability_id = None

# Agent action receipts (Receipt Internet v0 - event side)
try:
    from .agent_action import (  # noqa: F401
        AgentActionReceipt,
        CapabilityRefusalReceipt,
        create_agent_action_receipt,
        create_capability_refusal_receipt,
        compute_input_hash,
        compute_output_hash,
    )
except Exception:
    AgentActionReceipt = None
    CapabilityRefusalReceipt = None
    create_agent_action_receipt = None
    create_capability_refusal_receipt = None
    compute_input_hash = None
    compute_output_hash = None

# Kill switch receipts (Emergency capability revocation)
try:
    from .kill_switch import (  # noqa: F401
        KillSwitchMode,
        KillSwitchTargetType,
        RecoveryStatus,
        KeyRevocationReason,
        KillSwitchTarget,
        KillSwitchReceipt,
        KillSwitchDeactivationReceipt,
        KeyRevocationReceipt,
        create_kill_switch_receipt,
        create_key_revocation_receipt,
    )
except Exception:
    KillSwitchMode = None
    KillSwitchTargetType = None
    RecoveryStatus = None
    KeyRevocationReason = None
    KillSwitchTarget = None
    KillSwitchReceipt = None
    KillSwitchDeactivationReceipt = None
    KeyRevocationReceipt = None
    create_kill_switch_receipt = None
    create_key_revocation_receipt = None

# Policy recommendation receipts (Quintet → CCIO loop)
try:
    from .policy import (  # noqa: F401
        PolicyRecommendationReceipt,
        create_policy_recommendation_receipt,
    )
except Exception:
    PolicyRecommendationReceipt = None
    create_policy_recommendation_receipt = None

# Blockage receipts (Assay: structured proof of what can't be decided)
try:
    from .blockages import (  # noqa: F401
        IncompletenessReceipt,
        ContradictionReceipt,
        ParadoxReceipt,
        create_incompleteness_receipt,
        create_contradiction_receipt,
        create_paradox_receipt,
    )
except Exception:
    IncompletenessReceipt = None
    ContradictionReceipt = None
    ParadoxReceipt = None
    create_incompleteness_receipt = None
    create_contradiction_receipt = None
    create_paradox_receipt = None

# Membrane model (No Action Without Receipt invariant)
try:
    from .membrane import (  # noqa: F401
        EffectType,
        DomainProfile,
        SensitivityLevel,
        DOMAIN_REQUIRED_EFFECTS,
        get_required_effects,
        effect_requires_receipt,
        ObservationReceipt,
        create_observation_receipt,
        ObservationSessionReceipt,
        create_observation_session_receipt,
        MembraneOperation,
        InvariantCheckResult,
        check_no_action_without_receipt,
    )
except Exception:
    EffectType = None
    DomainProfile = None
    SensitivityLevel = None
    DOMAIN_REQUIRED_EFFECTS = None
    get_required_effects = None
    effect_requires_receipt = None
    ObservationReceipt = None
    create_observation_receipt = None
    ObservationSessionReceipt = None
    create_observation_session_receipt = None
    MembraneOperation = None
    InvariantCheckResult = None
    check_no_action_without_receipt = None

# Model call receipts (Patent Claim 1 - audit trail for AI operations)
try:
    from .model_call import (  # noqa: F401
        ModelCallReceipt,
        create_model_call_receipt,
    )
except Exception:
    ModelCallReceipt = None
    create_model_call_receipt = None

# Capability use receipts (Patent Claim 17 - max_calls tracking)
try:
    from .capability_use import (  # noqa: F401
        CapabilityUseReceipt,
        create_capability_use_receipt,
    )
except Exception:
    CapabilityUseReceipt = None
    create_capability_use_receipt = None

# Guardian verdict receipts (Patent Claim 15 - verdict contents)
try:
    from .guardian_verdict import (  # noqa: F401
        DignityFacetScore,
        GuardianVerdictReceipt,
        create_guardian_verdict,
    )
except Exception:
    DignityFacetScore = None
    GuardianVerdictReceipt = None
    create_guardian_verdict = None

# Dignity budget refusal receipts (Patent Claim 14 - dignity floor)
try:
    from .dignity_budget import (  # noqa: F401
        DignityBudgetRefusalReceipt,
        create_dignity_budget_refusal,
    )
except Exception:
    DignityBudgetRefusalReceipt = None
    create_dignity_budget_refusal = None
