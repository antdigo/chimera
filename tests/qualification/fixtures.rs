pub struct CanarySet {
    pub run_id: uuid::Uuid,
    pub host: String,
    pub peer: String,
    pub supervisor: String,
    pub credential: String,
}

pub fn make_canaries(run_id: uuid::Uuid) -> CanarySet {
    let canary = |role| format!("chimera-qualification:{run_id}:{role}");
    CanarySet {
        run_id,
        host: canary("host"),
        peer: canary("peer"),
        supervisor: canary("supervisor"),
        credential: canary("credential"),
    }
}

/// Closed previous-tenant manifest, generated from the harness's expected UUIDs.
/// E1 must seed and search every category in every next-wave attempt; artifact
/// integration being absent is missing evidence, never an empty successful scan.
pub fn tenant_canaries(attempts: &[uuid::Uuid]) -> Vec<String> {
    attempts
        .iter()
        .flat_map(|attempt| {
            [
                "filesystem",
                "process",
                "environment",
                "docker",
                "cache",
                "artifact",
                "credential",
            ]
            .map(|kind| format!("chimera-qualification:{attempt}:{kind}"))
        })
        .collect()
}

/// E1 must start this registry inside `attempt`, on a Docker network reachable
/// by that attempt's BuildKit. This is an intention, not a running registry.
/// It creates `network`, injects QUALIFICATION_NETWORK, arranges attempt-local
/// DNS/routing for the job CLI and daemon, and supplies registry TLS/trust.
/// Never map it to a host listener or add an egress-policy exception. Inject the
/// password as QUALIFICATION_PASSWORD in the existing job secret context so the
/// job engine's normal masker applies. Neither credentials nor auth config are
/// serializable report facts, and no Debug implementation reveals the password.
pub struct SyntheticRegistry {
    pub attempt: uuid::Uuid,
    pub address: &'static str,
    pub network: String,
    password: String,
    masks: Vec<chimera::job::masking::SecretMask>,
}

impl SyntheticRegistry {
    pub fn new(attempt: uuid::Uuid) -> Result<Self, super::catalog::Reason> {
        if attempt.is_nil() {
            return Err(super::catalog::Reason::InvalidConfig);
        }
        let password = format!("synthetic-{}", uuid::Uuid::new_v4());
        let mut masks = Vec::new();
        chimera::job::masking::append_value(&mut masks, &password);
        Ok(Self {
            attempt,
            address: "qualification-registry:5000",
            network: format!("qualification-{}", attempt.simple()),
            password,
            masks,
        })
    }

    pub fn username(&self) -> &'static str {
        "synthetic-qualification"
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn redact(&self, text: &str) -> String {
        chimera::job::masking::apply(&self.masks, text)
    }
}
