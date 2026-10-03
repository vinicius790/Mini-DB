//! Eleição de líder no estilo Raft sobre a replicação lógica existente.
//!
//! Só a parte de eleição do Raft: termo, um voto por termo, maioria estrita,
//! batimentos do líder e comparação de logs. O "log" é o da replicação
//! ([`crate::replication`]): a posição de um nó é `(época, LSN)` ([`LogPos`]) e o
//! termo vencedor vira a época do novo primário, então o fencing por época que já
//! existe passa a recusar o líder antigo. Não há AppendEntries próprio, snapshots
//! do log do Raft, mudança de membros em execução nem PreVote.
//!
//! [`Node`] é uma máquina de estados pura: sem rede, sem relógio real (o instante
//! entra por parâmetro) e sem disco. Quem a dirige grava [`Node::hard_state`]
//! ([`save_hard_state`]) antes de enviar qualquer mensagem produzida por ela.

use crate::error::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

/// Identificador de um nó (`cluster_id`; 0 é inválido).
pub type NodeId = u64;

/// Arquivo do estado persistente da eleição, no diretório do banco.
pub const STATE_FILE: &str = "raft-state";

/// Tamanho fixo de uma mensagem codificada.
const MESSAGE_LEN: usize = 34;

/// Posição do log de um nó: época dos dados e LSN dentro dela. A ordem é
/// lexicográfica (época antes do LSN), como "termo do último registro, depois
/// índice" no Raft.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct LogPos {
    pub epoch: u64,
    pub lsn: u64,
}

/// Estado que precisa sobreviver a reinícios: termo atual e voto nele.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HardState {
    pub term: u64,
    pub voted_for: Option<NodeId>,
}

/// Papel do nó na eleição.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Segue o líder do termo (se conhecido).
    Follower,
    /// Pediu votos neste termo.
    Candidate,
    /// Venceu a eleição deste termo.
    Leader,
}

/// Mensagens entre nós.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Message {
    /// Pedido de voto com a posição do log do candidato.
    RequestVote {
        term: u64,
        candidate: NodeId,
        last: LogPos,
    },
    /// Resposta a [`Message::RequestVote`].
    Vote {
        term: u64,
        voter: NodeId,
        granted: bool,
    },
    /// Batimento do líder.
    Heartbeat { term: u64, leader: NodeId },
    /// Resposta a [`Message::Heartbeat`].
    HeartbeatAck { term: u64, from: NodeId },
}

/// O que a camada de rede deve fazer depois de um evento.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Envia `msg` ao par `to`.
    Send { to: NodeId, msg: Message },
    /// Responde ao remetente da mensagem tratada.
    Reply(Message),
    /// Venceu a eleição: promover este nó com época = `term`.
    BecomeLeader { term: u64 },
    /// Deixou de ser líder: parar de aceitar escritas.
    StepDown,
}

/// Relógios da eleição.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// O timeout de eleição é sorteado em `[election_min, election_max)` a cada
    /// reinício do relógio.
    pub election_min: Duration,
    pub election_max: Duration,
    /// Semente do sorteio (os testes usam valores fixos).
    pub seed: u64,
}

impl Timing {
    /// Timeout de eleição entre `base` e `2 * base`; batimento a `base / 5`.
    pub fn new(base: Duration, seed: u64) -> Self {
        Self {
            election_min: base,
            election_max: base * 2,
            seed,
        }
    }

    /// Intervalo entre batimentos do líder.
    pub fn heartbeat(&self) -> Duration {
        self.election_min / 5
    }
}

/// Máquina de estados da eleição de um nó.
pub struct Node {
    id: NodeId,
    peers: Vec<NodeId>,
    hard: HardState,
    state: State,
    leader: Option<NodeId>,
    timing: Timing,
    rng: u64,
    /// Seguidor ou candidato: próxima eleição. Líder: próximo batimento.
    deadline: Instant,
    votes: BTreeSet<NodeId>,
    /// Líder: quando cada par respondeu um batimento pela última vez.
    contact: BTreeMap<NodeId, Instant>,
}

impl Node {
    /// Nó que (re)começa como seguidor com o estado persistido `hard`.
    pub fn new(
        id: NodeId,
        peers: Vec<NodeId>,
        hard: HardState,
        timing: Timing,
        now: Instant,
    ) -> Self {
        let mut node = Self {
            id,
            peers,
            hard,
            state: State::Follower,
            leader: None,
            timing,
            rng: timing.seed | 1,
            deadline: now,
            votes: BTreeSet::new(),
            contact: BTreeMap::new(),
        };
        node.reset_election(now);
        node
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn term(&self) -> u64 {
        self.hard.term
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Líder conhecido do termo atual (o próprio nó, se for o líder).
    pub fn leader(&self) -> Option<NodeId> {
        self.leader
    }

    /// O que gravar antes de enviar qualquer mensagem.
    pub fn hard_state(&self) -> HardState {
        self.hard
    }

    /// Votos necessários: maioria estrita do cluster, contando este nó.
    pub fn majority(&self) -> usize {
        let nodes = self.peers.len() + 1;
        nodes / 2 + 1
    }

    /// Seguidor ou candidato cujo timeout de eleição venceu: o próximo
    /// [`Node::on_timeout`] inicia uma eleição (se o nó tiver posição de log).
    pub fn election_due(&self, now: Instant) -> bool {
        self.state != State::Leader && now >= self.deadline
    }

    /// Avança os relógios. O líder manda batimentos e desiste se ficou um timeout
    /// de eleição sem resposta da maioria; seguidor ou candidato sem notícias por
    /// um timeout se candidata com termo + 1. `last` é a posição do log deste nó;
    /// com `None` (ressincronizando) ele não se candidata.
    pub fn on_timeout(&mut self, now: Instant, last: Option<LogPos>) -> Vec<Action> {
        if self.state == State::Leader {
            return self.lead(now);
        }
        if now < self.deadline {
            return Vec::new();
        }
        self.reset_election(now);
        let last = match last {
            Some(last) => last,
            None => return Vec::new(),
        };
        self.hard = HardState {
            term: self.hard.term + 1,
            voted_for: Some(self.id),
        };
        self.state = State::Candidate;
        self.leader = None;
        self.votes = BTreeSet::from([self.id]);
        if self.votes.len() >= self.majority() {
            return self.become_leader(now);
        }
        let (term, candidate) = (self.hard.term, self.id);
        let request = Message::RequestVote {
            term,
            candidate,
            last,
        };
        self.broadcast(request)
    }

    /// O líder desiste por fora do protocolo (por exemplo, a promoção falhou).
    pub fn resign(&mut self, now: Instant) -> Vec<Action> {
        if self.state != State::Leader {
            return Vec::new();
        }
        self.become_follower(now);
        vec![Action::StepDown]
    }

    /// Pedido de voto: concede no máximo um voto por termo, e só a candidato cujo
    /// log (`last`) é pelo menos tão atualizado quanto o deste nó (`mine`). Sem
    /// posição (`mine = None`, ressincronizando) o nó nunca vota.
    pub fn on_request_vote(
        &mut self,
        now: Instant,
        term: u64,
        candidate: NodeId,
        last: LogPos,
        mine: Option<LogPos>,
    ) -> Vec<Action> {
        let mut out = self.observe(term, now);
        let granted = term == self.hard.term
            && self.hard.voted_for.is_none_or(|v| v == candidate)
            && mine.is_some_and(|m| last >= m);
        if granted {
            self.hard.voted_for = Some(candidate);
            self.reset_election(now);
        }
        let (term, voter) = (self.hard.term, self.id);
        let reply = Message::Vote {
            term,
            voter,
            granted,
        };
        out.push(Action::Reply(reply));
        out
    }

    /// Resposta a um pedido de voto deste nó.
    pub fn on_vote(
        &mut self,
        now: Instant,
        term: u64,
        voter: NodeId,
        granted: bool,
    ) -> Vec<Action> {
        let mut out = self.observe(term, now);
        let counts = granted
            && self.state == State::Candidate
            && term == self.hard.term
            && self.peers.contains(&voter);
        if counts {
            self.votes.insert(voter);
            if self.votes.len() >= self.majority() {
                out.extend(self.become_leader(now));
            }
        }
        out
    }

    /// Batimento de um líder: com o termo atual (ou maior) o nó passa a segui-lo
    /// e adia a eleição. A resposta leva o termo deste nó, para um líder antigo
    /// descobrir que foi substituído.
    pub fn on_heartbeat(&mut self, now: Instant, term: u64, leader: NodeId) -> Vec<Action> {
        let mut out = self.observe(term, now);
        if term == self.hard.term && self.state != State::Leader {
            self.state = State::Follower;
            self.votes.clear();
            self.leader = Some(leader);
            self.reset_election(now);
        }
        let (term, from) = (self.hard.term, self.id);
        out.push(Action::Reply(Message::HeartbeatAck { term, from }));
        out
    }

    /// Resposta a um batimento: o par ainda ouve este líder.
    pub fn on_heartbeat_ack(&mut self, now: Instant, term: u64, from: NodeId) -> Vec<Action> {
        let out = self.observe(term, now);
        let current = self.state == State::Leader && term == self.hard.term;
        if current && self.peers.contains(&from) {
            self.contact.insert(from, now);
        }
        out
    }

    /// Despacha `msg` para o tratador certo (`mine` só vale para pedidos de voto).
    pub fn on_message(&mut self, now: Instant, msg: Message, mine: Option<LogPos>) -> Vec<Action> {
        match msg {
            Message::RequestVote {
                term,
                candidate,
                last,
            } => self.on_request_vote(now, term, candidate, last, mine),
            Message::Vote {
                term,
                voter,
                granted,
            } => self.on_vote(now, term, voter, granted),
            Message::Heartbeat { term, leader } => self.on_heartbeat(now, term, leader),
            Message::HeartbeatAck { term, from } => self.on_heartbeat_ack(now, term, from),
        }
    }

    fn lead(&mut self, now: Instant) -> Vec<Action> {
        let window = self.timing.election_min;
        let alive = self
            .contact
            .values()
            .filter(|&&at| now.saturating_duration_since(at) <= window)
            .count();
        if alive + 1 < self.majority() {
            self.become_follower(now);
            return vec![Action::StepDown];
        }
        if now < self.deadline {
            return Vec::new();
        }
        self.deadline = now + self.timing.heartbeat();
        self.heartbeats()
    }

    fn heartbeats(&self) -> Vec<Action> {
        let (term, leader) = (self.hard.term, self.id);
        self.broadcast(Message::Heartbeat { term, leader })
    }

    fn broadcast(&self, msg: Message) -> Vec<Action> {
        self.peers
            .iter()
            .map(|&to| Action::Send { to, msg })
            .collect()
    }

    fn become_leader(&mut self, now: Instant) -> Vec<Action> {
        self.state = State::Leader;
        self.leader = Some(self.id);
        self.votes.clear();
        // Carência de um timeout para os pares responderem ao primeiro batimento.
        self.contact = self.peers.iter().map(|&peer| (peer, now)).collect();
        self.deadline = now + self.timing.heartbeat();
        let term = self.hard.term;
        let mut out = vec![Action::BecomeLeader { term }];
        out.extend(self.heartbeats());
        out
    }

    fn become_follower(&mut self, now: Instant) {
        self.state = State::Follower;
        self.leader = None;
        self.votes.clear();
        self.contact.clear();
        self.reset_election(now);
    }

    /// Termo maior visto em qualquer mensagem: adota-o sem voto e vira seguidor.
    fn observe(&mut self, term: u64, now: Instant) -> Vec<Action> {
        if term <= self.hard.term {
            return Vec::new();
        }
        let was_leader = self.state == State::Leader;
        self.hard = HardState {
            term,
            voted_for: None,
        };
        if self.state == State::Follower {
            self.leader = None;
        } else {
            self.become_follower(now);
        }
        if was_leader {
            vec![Action::StepDown]
        } else {
            Vec::new()
        }
    }

    fn reset_election(&mut self, now: Instant) {
        // xorshift64: sorteio determinístico a partir da semente.
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        let (min, max) = (self.timing.election_min, self.timing.election_max);
        let span = max.saturating_sub(min).as_millis() as u64;
        let extra = self.rng % span.max(1);
        self.deadline = now + min + Duration::from_millis(extra);
    }
}

impl Message {
    /// Termo de quem enviou.
    pub fn term(&self) -> u64 {
        match *self {
            Message::RequestVote { term, .. }
            | Message::Vote { term, .. }
            | Message::Heartbeat { term, .. }
            | Message::HeartbeatAck { term, .. } => term,
        }
    }

    /// `[tipo:u8][termo:u64][nó:u64][época:u64][lsn:u64][voto:u8]`.
    pub fn encode(&self) -> Vec<u8> {
        let none = LogPos::default();
        let (kind, term, id, last, flag) = match *self {
            Message::RequestVote {
                term,
                candidate,
                last,
            } => (1u8, term, candidate, last, false),
            Message::Vote {
                term,
                voter,
                granted,
            } => (2, term, voter, none, granted),
            Message::Heartbeat { term, leader } => (3, term, leader, none, false),
            Message::HeartbeatAck { term, from } => (4, term, from, none, false),
        };
        let mut out = Vec::with_capacity(MESSAGE_LEN);
        out.push(kind);
        for word in [term, id, last.epoch, last.lsn] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.push(u8::from(flag));
        out
    }

    /// Inverso de [`Message::encode`]; `None` para qualquer corpo malformado.
    pub fn decode(body: &[u8]) -> Option<Message> {
        if body.len() != MESSAGE_LEN {
            return None;
        }
        let word = |i: usize| {
            let at = 1 + 8 * i;
            u64::from_le_bytes(body[at..at + 8].try_into().expect("8 bytes"))
        };
        let (term, id) = (word(0), word(1));
        let last = LogPos {
            epoch: word(2),
            lsn: word(3),
        };
        Some(match (body[0], body[MESSAGE_LEN - 1]) {
            (1, 0) => Message::RequestVote {
                term,
                candidate: id,
                last,
            },
            (2, flag @ 0..=1) => Message::Vote {
                term,
                voter: id,
                granted: flag == 1,
            },
            (3, 0) => Message::Heartbeat { term, leader: id },
            (4, 0) => Message::HeartbeatAck { term, from: id },
            _ => return None,
        })
    }
}

/// Lê `cluster_peers`: `id@endereço` separados por vírgula, por exemplo
/// `2@10.0.0.2:7001,3@10.0.0.3:7001` (o endereço de replicação de cada par).
pub fn parse_peers(text: &str) -> Result<Vec<(NodeId, String)>> {
    let mut peers: Vec<(NodeId, String)> = Vec::new();
    for item in text.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (id, addr) = item.split_once('@').unwrap_or(("", ""));
        let id = id.trim().parse::<NodeId>().unwrap_or(0);
        let addr = addr.trim();
        if id == 0 || addr.is_empty() {
            return Err(Error::Other(format!(
                "cluster_peers: entrada inválida {item:?} (esperado id@endereço, id > 0)"
            )));
        }
        if peers.iter().any(|(other, _)| *other == id) {
            return Err(Error::Other(format!("cluster_peers: id {id} repetido")));
        }
        peers.push((id, addr.to_string()));
    }
    Ok(peers)
}

/// Lê o estado persistido em `dir` (ausente = termo 0, sem voto).
pub fn load_hard_state(dir: &Path) -> Result<HardState> {
    let text = match fs::read_to_string(dir.join(STATE_FILE)) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HardState::default()),
        Err(e) => return Err(e.into()),
    };
    let mut parts = text.split_whitespace();
    let term = parts.next().and_then(|t| t.parse().ok());
    let voted_for = match parts.next() {
        Some("-") => Some(None),
        Some(id) => id.parse::<NodeId>().ok().map(Some),
        None => None,
    };
    match (term, voted_for) {
        (Some(term), Some(voted_for)) => Ok(HardState { term, voted_for }),
        _ => Err(Error::Other(format!("{STATE_FILE} corrompido: {text:?}"))),
    }
}

/// Grava `hard` em `dir` de forma atômica e durável: arquivo temporário com
/// fsync, rename e fsync do diretório (onde o sistema permite abri-lo).
pub fn save_hard_state(dir: &Path, hard: HardState) -> Result<()> {
    let voted = match hard.voted_for {
        Some(id) => id.to_string(),
        None => "-".to_string(),
    };
    let tmp = dir.join(format!("{STATE_FILE}.tmp"));
    let mut file = fs::File::create(&tmp)?;
    file.write_all(format!("{} {voted}\n", hard.term).as_bytes())?;
    file.sync_all()?;
    drop(file);
    fs::rename(tmp, dir.join(STATE_FILE))?;
    // No Windows não há como abrir o diretório: o rename fica a cargo do sistema.
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const START: LogPos = LogPos { epoch: 0, lsn: 0 };

    fn timing(seed: u64) -> Timing {
        Timing::new(Duration::from_millis(150), seed)
    }

    fn sent_to(out: &[Action], to: NodeId) -> Message {
        out.iter()
            .find_map(|a| match *a {
                Action::Send { to: t, msg } if t == to => Some(msg),
                _ => None,
            })
            .expect("mensagem para o par")
    }

    fn reply_of(out: &[Action]) -> Message {
        out.iter()
            .find_map(|a| match *a {
                Action::Reply(msg) => Some(msg),
                _ => None,
            })
            .expect("resposta")
    }

    fn granted(out: &[Action]) -> bool {
        matches!(reply_of(out), Message::Vote { granted: true, .. })
    }

    /// Cluster em memória com entrega controlada: mensagens vão para uma fila e
    /// só chegam se o destino estiver no ar e o enlace não estiver cortado.
    struct Sim {
        nodes: Vec<Node>,
        logs: Vec<Option<LogPos>>,
        up: Vec<bool>,
        cut: BTreeSet<(NodeId, NodeId)>,
        now: Instant,
        /// Termo -> vencedor; a inserção confere um único líder por termo.
        leaders: BTreeMap<u64, NodeId>,
        queue: VecDeque<(NodeId, NodeId, Message)>,
    }

    impl Sim {
        fn new(n: u64, seed: u64) -> Self {
            let now = Instant::now();
            let nodes = (1..=n)
                .map(|id| {
                    let peers = (1..=n).filter(|&p| p != id).collect();
                    let hard = HardState::default();
                    Node::new(id, peers, hard, timing(seed * 31 + id), now)
                })
                .collect();
            Self {
                nodes,
                logs: vec![Some(START); n as usize],
                up: vec![true; n as usize],
                cut: BTreeSet::new(),
                now,
                leaders: BTreeMap::new(),
                queue: VecDeque::new(),
            }
        }

        fn node(&self, id: NodeId) -> &Node {
            &self.nodes[id as usize - 1]
        }

        /// Corta, nos dois sentidos, todo enlace entre `group` e o resto.
        fn isolate(&mut self, group: &[NodeId]) {
            let n = self.nodes.len() as u64;
            for &a in group {
                for b in (1..=n).filter(|b| !group.contains(b)) {
                    self.cut.insert((a, b));
                    self.cut.insert((b, a));
                }
            }
        }

        fn apply(&mut self, from: NodeId, out: Vec<Action>, asker: Option<NodeId>) {
            for action in out {
                match action {
                    Action::Send { to, msg } => self.queue.push_back((from, to, msg)),
                    Action::Reply(msg) => {
                        let to = asker.expect("resposta sem pedido");
                        self.queue.push_back((from, to, msg));
                    }
                    Action::BecomeLeader { term } => {
                        let previous = self.leaders.insert(term, from);
                        assert_eq!(previous, None, "dois líderes no termo {term}");
                    }
                    Action::StepDown => {}
                }
            }
        }

        fn deliver(&mut self) {
            while let Some((from, to, msg)) = self.queue.pop_front() {
                let i = to as usize - 1;
                if !self.up[i] || self.cut.contains(&(from, to)) {
                    continue;
                }
                let out = self.nodes[i].on_message(self.now, msg, self.logs[i]);
                self.apply(to, out, Some(from));
            }
        }

        /// Avança o relógio em passos de 10 ms, entregando tudo a cada passo.
        fn run(&mut self, total: Duration) {
            let end = self.now + total;
            while self.now < end {
                self.now += Duration::from_millis(10);
                for id in 1..=self.nodes.len() as u64 {
                    let i = id as usize - 1;
                    if self.up[i] {
                        let out = self.nodes[i].on_timeout(self.now, self.logs[i]);
                        self.apply(id, out, None);
                    }
                }
                self.deliver();
            }
        }

        fn current_leaders(&self) -> Vec<NodeId> {
            self.nodes
                .iter()
                .zip(&self.up)
                .filter(|(node, up)| **up && node.state() == State::Leader)
                .map(|(node, _)| node.id())
                .collect()
        }
    }

    #[test]
    fn elects_exactly_one_leader_with_three_and_five_nodes() {
        for n in [3, 5] {
            for seed in 1..=20 {
                let mut sim = Sim::new(n, seed);
                sim.run(Duration::from_secs(3));
                let leaders = sim.current_leaders();
                assert_eq!(leaders.len(), 1, "n={n} seed={seed}: {leaders:?}");
                let term = sim.node(leaders[0]).term();
                for id in 1..=n {
                    assert_eq!(sim.node(id).leader(), Some(leaders[0]), "seed={seed}");
                    assert_eq!(sim.node(id).term(), term);
                }
            }
        }
    }

    #[test]
    fn node_with_stale_log_never_wins() {
        for seed in 1..=10 {
            let mut sim = Sim::new(3, seed);
            let behind = LogPos { epoch: 1, lsn: 10 };
            let ahead = LogPos { epoch: 1, lsn: 50 };
            sim.logs = vec![Some(behind), Some(ahead), Some(ahead)];
            // O nó atrasado é sempre o primeiro a estourar o timeout (100 < 150 ms).
            sim.nodes[0].timing = Timing::new(Duration::from_millis(100), seed);
            sim.nodes[0].timing.election_max = Duration::from_millis(101);
            sim.nodes[0].reset_election(sim.now);
            sim.run(Duration::from_secs(3));
            assert!(sim.leaders.values().all(|&id| id != 1), "seed={seed}");
            assert!(!sim.leaders.is_empty(), "alguém foi eleito");
            assert_eq!(sim.current_leaders().len(), 1);
        }
    }

    #[test]
    fn vote_compares_epoch_before_lsn_and_a_resyncing_node_never_votes() {
        let now = Instant::now();
        let mut node = Node::new(3, vec![1, 2], HardState::default(), timing(7), now);
        let old_big = LogPos { epoch: 1, lsn: 99 };
        let new_small = LogPos { epoch: 2, lsn: 1 };
        let out = node.on_request_vote(now, 1, 1, old_big, Some(new_small));
        assert!(!granted(&out), "época menor perde mesmo com LSN maior");
        let out = node.on_request_vote(now, 2, 2, new_small, Some(old_big));
        assert!(granted(&out));
        let out = node.on_request_vote(now, 3, 1, new_small, None);
        assert!(!granted(&out), "ressincronizando não vota");
        assert_eq!(node.term(), 3, "mas adota o termo");
        let later = now + Duration::from_secs(10);
        let out = node.on_timeout(later, None);
        assert!(out.is_empty(), "ressincronizando não se candidata");
        assert_eq!((node.state(), node.term()), (State::Follower, 3));
    }

    #[test]
    fn minority_partition_never_elects() {
        for seed in 1..=10 {
            let mut sim = Sim::new(5, seed);
            sim.isolate(&[1, 2]);
            sim.run(Duration::from_secs(3));
            assert!(sim.leaders.values().all(|&id| id >= 3), "seed={seed}");
            let leaders = sim.current_leaders();
            assert_eq!(leaders.len(), 1);
            assert!(leaders[0] >= 3);
        }
    }

    #[test]
    fn isolated_leader_steps_down_and_the_majority_moves_on() {
        for seed in 1..=10 {
            let mut sim = Sim::new(3, seed);
            sim.run(Duration::from_secs(2));
            let old = sim.current_leaders()[0];
            let old_term = sim.node(old).term();
            sim.isolate(&[old]);
            sim.run(Duration::from_secs(2));
            assert_ne!(sim.node(old).state(), State::Leader, "seed={seed}");
            let leaders = sim.current_leaders();
            assert_eq!(leaders.len(), 1);
            assert_ne!(leaders[0], old);
            assert!(sim.node(leaders[0]).term() > old_term);
            // Curada a partição, o antigo líder volta a seguir alguém.
            sim.cut.clear();
            sim.run(Duration::from_secs(2));
            let leaders = sim.current_leaders();
            assert_eq!(leaders.len(), 1);
            assert_eq!(sim.node(old).leader(), Some(leaders[0]));
        }
    }

    #[test]
    fn split_vote_is_resolved_in_a_later_term() {
        let mut sim = Sim::new(4, 3);
        // 1 e 2 se candidatam no mesmo instante; 3 ouve o 1 primeiro e 4, o 2.
        sim.now += Duration::from_secs(1);
        let now = sim.now;
        let a = sim.nodes[0].on_timeout(now, Some(START));
        let b = sim.nodes[1].on_timeout(now, Some(START));
        let split = sim.node(1).term();
        assert_eq!(sim.node(2).term(), split);
        sim.queue.push_back((1, 3, sent_to(&a, 3)));
        sim.queue.push_back((2, 4, sent_to(&b, 4)));
        sim.queue.push_back((1, 4, sent_to(&a, 4)));
        sim.queue.push_back((2, 3, sent_to(&b, 3)));
        sim.queue.push_back((1, 2, sent_to(&a, 2)));
        sim.queue.push_back((2, 1, sent_to(&b, 1)));
        sim.deliver();
        assert_eq!(sim.node(1).state(), State::Candidate);
        assert_eq!(sim.node(2).state(), State::Candidate);
        assert!(sim.leaders.is_empty(), "empate: ninguém tem 3 de 4 votos");
        sim.run(Duration::from_secs(3));
        let leaders = sim.current_leaders();
        assert_eq!(leaders.len(), 1);
        assert!(sim.node(leaders[0]).term() > split);
        assert!(!sim.leaders.contains_key(&split));
    }

    #[test]
    fn persisted_vote_is_not_given_twice_in_the_same_term_after_restart() {
        let name = format!("minidb-raft-unit-{}", std::process::id());
        let dir = std::env::temp_dir().join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (now, pos) = (Instant::now(), Some(START));
        assert_eq!(load_hard_state(&dir).unwrap(), HardState::default());
        let mut node = Node::new(3, vec![1, 2], HardState::default(), timing(1), now);
        let out = node.on_request_vote(now, 5, 1, START, pos);
        assert!(granted(&out));
        save_hard_state(&dir, node.hard_state()).unwrap();
        drop(node);
        // "Reinício": só o que está no disco sobrevive.
        let hard = load_hard_state(&dir).unwrap();
        let expected = HardState {
            term: 5,
            voted_for: Some(1),
        };
        assert_eq!(hard, expected);
        let mut node = Node::new(3, vec![1, 2], hard, timing(1), now);
        let out = node.on_request_vote(now, 5, 2, START, pos);
        assert!(!granted(&out), "outro candidato no mesmo termo");
        let out = node.on_request_vote(now, 5, 1, START, pos);
        assert!(granted(&out), "o mesmo candidato pode repetir o pedido");
        let out = node.on_request_vote(now, 6, 2, START, pos);
        assert!(granted(&out), "termo novo, voto novo");
        fs::write(dir.join(STATE_FILE), "lixo").unwrap();
        assert!(load_hard_state(&dir).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn messages_roundtrip_and_peers_parse() {
        let last = LogPos {
            epoch: 3,
            lsn: u64::MAX,
        };
        let (term, leader, from) = (9, 1, 2);
        let msgs = [
            Message::RequestVote {
                term: 7,
                candidate: 2,
                last,
            },
            Message::Vote {
                term: 7,
                voter: 3,
                granted: true,
            },
            Message::Heartbeat { term, leader },
            Message::HeartbeatAck { term, from },
        ];
        for msg in msgs {
            let bytes = msg.encode();
            assert_eq!(Message::decode(&bytes), Some(msg));
            assert_eq!(Message::decode(&bytes[..bytes.len() - 1]), None);
        }
        let mut bad = msgs[2].encode();
        bad[0] = 9;
        assert_eq!(Message::decode(&bad), None);
        let peers = parse_peers(" 2@a:1, 3@b:2 ").unwrap();
        let expected = vec![(2, "a:1".to_string()), (3, "b:2".to_string())];
        assert_eq!(peers, expected);
        assert!(parse_peers("").unwrap().is_empty());
        for bad in ["a:1", "0@a:1", "2@", "2@a:1,2@b:1"] {
            assert!(parse_peers(bad).is_err(), "{bad}");
        }
    }
}
