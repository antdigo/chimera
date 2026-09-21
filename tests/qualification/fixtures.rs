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
