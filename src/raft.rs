//! Eleição de líder no estilo Raft sobre a replicação lógica existente.
//!
//! Termo, um voto por termo, maioria estrita, batimentos do líder, comparação de
//! logs, PreVote e troca de um membro por vez. O "log" é o da replicação
//! ([`crate::replication`]): a posição de um nó é `(época, LSN)` ([`LogPos`]) e o
//! termo vencedor vira a época do novo primário, então o fencing por época que já
//! existe passa a recusar o líder antigo. Não há AppendEntries próprio nem
//! snapshots do log do Raft.
//!
//! **PreVote.** Antes de subir o termo, o nó pergunta aos membros se votariam
//! nele; quem ouviu um líder há menos de um timeout de eleição, ou tem log mais
//! atualizado, diz não. Um nó que ficou isolado não volta com termo alto
//! forçando uma eleição.
//!
//! **Membros.** A configuração ([`Membership`]) é um registro do próprio log
//! replicado: cada nó usa a mais recente que tem nos dados ([`Node::set_config`]),
//! votos e maioria contam só os membros dela e o líder troca um membro por vez
//! ([`Node::propose`]), o "single-server change" do Raft. Um nó fora da
//! configuração não se candidata e o voto dele não conta.
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

/// Configuração de membros: quem vota e o endereço de replicação de cada um.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Membership {
    /// 0 = a inicial (`cluster_peers`); cada troca soma 1.
    pub index: u64,
    pub members: BTreeMap<NodeId, String>,
}

/// Troca de um membro.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// Entra o nó `id`, com o endereço de replicação dado.
    Add(NodeId, String),
    /// Sai o nó `id`.
    Remove(NodeId),
}

impl Membership {
    /// Votos necessários: maioria estrita dos membros.
    pub fn majority(&self) -> usize {
        self.members.len() / 2 + 1
    }

    pub fn contains(&self, id: NodeId) -> bool {
        self.members.contains_key(&id)
    }

    /// A configuração seguinte, com uma única troca.
    pub fn with(&self, change: &Change) -> Result<Membership> {
        let mut members = self.members.clone();
        match change {
            Change::Add(id, addr) => {
                let bad = |c: char| c == ',' || c.is_whitespace();
                if *id == 0 || addr.is_empty() || addr.contains(bad) {
                    return Err(invalid(format!("nó inválido: {id}@{addr:?}")));
                }
                if members.insert(*id, addr.clone()).is_some() {
                    return Err(invalid(format!("o nó {id} já é membro")));
                }
            }
            Change::Remove(id) => {
                if members.remove(id).is_none() {
                    return Err(invalid(format!("o nó {id} não é membro")));
                }
                if members.is_empty() {
                    return Err(invalid("o último membro não pode sair".into()));
                }
            }
        }
        let index = self.index + 1;
        Ok(Membership { index, members })
    }

    /// `índice id@endereço,id@endereço…`, como fica gravado nos dados.
    pub fn encode(&self) -> String {
        let members: Vec<String> = self
            .members
            .iter()
            .map(|(id, addr)| format!("{id}@{addr}"))
            .collect();
        format!("{} {}", self.index, members.join(","))
    }

    /// Inverso de [`Membership::encode`].
    pub fn decode(text: &str) -> Result<Membership> {
        let parsed = text.split_once(' ').and_then(|(index, members)| {
            let index = index.parse::<u64>().ok()?;
            let members: BTreeMap<NodeId, String> =
                parse_peers(members).ok()?.into_iter().collect();
            (!members.is_empty()).then_some(Membership { index, members })
        });
        let corrupt = || Error::Other(format!("configuração do cluster corrompida: {text:?}"));
        parsed.ok_or_else(corrupt)
    }
}

fn invalid(why: String) -> Error {
    Error::InvalidInput(why)
}

fn unavailable(why: &str) -> Error {
    Error::Unavailable(why.to_string())
}

/// Papel do nó na eleição.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Segue o líder do termo (se conhecido).
    Follower,
    /// Sem notícias do líder: perguntou aos membros se votariam nele (PreVote),
    /// ainda sem subir o termo.
    PreCandidate,
    /// Pediu votos neste termo.
    Candidate,
    /// Venceu a eleição deste termo.
    Leader,
}

/// Mensagens entre nós.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Message {
    /// Pré-voto: votaria em `candidate` no termo `term` (o dele + 1)? Quem
    /// responde não muda termo, voto nem relógio.
    PreVote {
        term: u64,
        candidate: NodeId,
        last: LogPos,
    },
    /// Resposta a [`Message::PreVote`]: `term` é o pedido, se concedido, ou o
    /// termo de quem recusou.
    PreVoteReply {
        term: u64,
        voter: NodeId,
        granted: bool,
    },
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

/// splitmix64: sementes vizinhas não podem dar a mesma sequência de sorteios (dois
/// nós em sincronia empatariam todas as eleições). Nunca devolve zero, que travaria
/// o xorshift.
fn mix(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (z ^ (z >> 31)).max(1)
}

/// Máquina de estados da eleição de um nó.
pub struct Node {
    id: NodeId,
    /// Configuração em vigor neste nó.
    config: Membership,
    /// Líder: troca proposta e ainda não confirmada (no máximo uma).
    pending: Option<Membership>,
    hard: HardState,
    state: State,
    leader: Option<NodeId>,
    timing: Timing,
    rng: u64,
    /// Seguidor ou (pré-)candidato: próxima eleição. Líder: próximo batimento.
    deadline: Instant,
    /// Pré-candidato: pré-votos recebidos. Candidato: votos.
    votes: BTreeSet<NodeId>,
    /// Pré-candidato: posição do log anunciada, usada também na candidatura.
    last: LogPos,
    /// Último batimento aceito de um líder (no PreVote: o líder segue vivo).
    heard: Option<Instant>,
    /// Líder: quando cada par respondeu um batimento pela última vez.
    contact: BTreeMap<NodeId, Instant>,
}

impl Node {
    /// Nó que (re)começa como seguidor com o estado persistido `hard` e a
    /// configuração `config`.
    pub fn new(
        id: NodeId,
        config: Membership,
        hard: HardState,
        timing: Timing,
        now: Instant,
    ) -> Self {
        let mut node = Self {
            id,
            config,
            pending: None,
            hard,
            state: State::Follower,
            leader: None,
            timing,
            rng: mix(timing.seed),
            deadline: now,
            votes: BTreeSet::new(),
            last: LogPos::default(),
            heard: None,
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

    /// Configuração em vigor neste nó.
    pub fn config(&self) -> &Membership {
        &self.config
    }

    /// Líder: a troca proposta e ainda não confirmada.
    pub fn pending(&self) -> Option<&Membership> {
        self.pending.as_ref()
    }

    /// Votos necessários: maioria estrita dos membros da configuração.
    pub fn majority(&self) -> usize {
        self.config.majority()
    }

    /// Este nó está na configuração em vigor (pode se candidatar e seu voto conta).
    pub fn is_member(&self) -> bool {
        self.config.contains(self.id)
    }

    /// Avança os relógios. O líder manda batimentos e desiste se ficou um timeout
    /// de eleição sem resposta da maioria. Seguidor ou candidato sem notícias por
    /// um timeout começa a pré-votação para o termo + 1, e só sobe o termo se a
    /// maioria dos membros concordar. `last` é a posição do log deste nó; com
    /// `None` (ressincronizando) ele não se candidata. Um nó fora da configuração
    /// nunca se candidata e larga o líder que parou de lhe mandar batimentos.
    pub fn on_timeout(&mut self, now: Instant, last: Option<LogPos>) -> Vec<Action> {
        if self.state == State::Leader {
            return self.lead(now);
        }
        if now < self.deadline {
            return Vec::new();
        }
        self.reset_election(now);
        if !self.is_member() {
            self.state = State::Follower;
            self.leader = None;
            self.votes.clear();
            return Vec::new();
        }
        let last = match last {
            Some(last) => last,
            None => return Vec::new(),
        };
        self.state = State::PreCandidate;
        self.leader = None;
        self.last = last;
        self.votes = BTreeSet::from([self.id]);
        if self.votes.len() >= self.majority() {
            return self.campaign(now);
        }
        let request = Message::PreVote {
            term: self.hard.term + 1,
            candidate: self.id,
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
    /// posição (`mine = None`) o nó nunca vota.
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

    /// Resposta a um pedido de voto deste nó: só contam votos de membros.
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
            && voter != self.id
            && self.config.contains(voter);
        if counts {
            self.votes.insert(voter);
            if self.votes.len() >= self.majority() {
                out.extend(self.become_leader(now));
            }
        }
        out
    }

    /// Pré-voto: concede se o termo pedido é maior que o deste nó, se o log do
    /// candidato é pelo menos tão atualizado e se este nó não ouviu um líder há
    /// menos de um timeout de eleição. Não muda termo, voto nem relógio.
    pub fn on_pre_vote(
        &self,
        now: Instant,
        term: u64,
        last: LogPos,
        mine: Option<LogPos>,
    ) -> Vec<Action> {
        let window = self.timing.election_min;
        let recent = |at: Instant| now.saturating_duration_since(at) < window;
        let alive = self.state == State::Leader || self.heard.is_some_and(recent);
        let granted = term > self.hard.term && !alive && mine.is_some_and(|m| last >= m);
        let reply = Message::PreVoteReply {
            term: if granted { term } else { self.hard.term },
            voter: self.id,
            granted,
        };
        vec![Action::Reply(reply)]
    }

    /// Resposta a um pré-voto deste nó: com a maioria dos membros, candidata-se
    /// de verdade. A recusa de quem está num termo maior faz este nó adotá-lo.
    pub fn on_pre_vote_reply(
        &mut self,
        now: Instant,
        term: u64,
        voter: NodeId,
        granted: bool,
    ) -> Vec<Action> {
        if !granted {
            return self.observe(term, now);
        }
        let counts = self.state == State::PreCandidate
            && term == self.hard.term + 1
            && voter != self.id
            && self.config.contains(voter);
        if counts {
            self.votes.insert(voter);
            if self.votes.len() >= self.majority() {
                return self.campaign(now);
            }
        }
        Vec::new()
    }

    /// Batimento de um líder: com o termo atual (ou maior) o nó passa a segui-lo
    /// e adia a eleição, mesmo fora da configuração (um nó que está entrando
    /// precisa achar o líder). A resposta leva o termo deste nó, para um líder
    /// antigo descobrir que foi substituído.
    pub fn on_heartbeat(&mut self, now: Instant, term: u64, leader: NodeId) -> Vec<Action> {
        let mut out = self.observe(term, now);
        if term == self.hard.term && self.state != State::Leader {
            self.state = State::Follower;
            self.votes.clear();
            self.leader = Some(leader);
            self.heard = Some(now);
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
        if current && from != self.id {
            self.contact.insert(from, now);
        }
        out
    }

    /// Despacha `msg` para o tratador certo (`mine` só vale para pedidos de voto
    /// e de pré-voto).
    pub fn on_message(&mut self, now: Instant, msg: Message, mine: Option<LogPos>) -> Vec<Action> {
        match msg {
            Message::PreVote { term, last, .. } => self.on_pre_vote(now, term, last, mine),
            Message::PreVoteReply {
                term,
                voter,
                granted,
            } => self.on_pre_vote_reply(now, term, voter, granted),
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

    /// Líder: propõe trocar um membro. Recusa se este nó não lidera ou se já há
    /// uma troca em andamento (uma por vez). Até [`Node::finish_change`], os
    /// batimentos vão também ao nó que está entrando, para ele seguir o líder.
    pub fn propose(&mut self, change: &Change) -> Result<Membership> {
        if self.state != State::Leader {
            return Err(unavailable("este nó não é o líder do cluster"));
        }
        if self.pending.is_some() {
            return Err(unavailable("já há uma troca de membros em andamento"));
        }
        let next = self.config.with(change)?;
        self.pending = Some(next.clone());
        Ok(next)
    }

    /// Fim da troca proposta no termo `term`: confirmada pela maioria da
    /// configuração nova, que passa a valer aqui (um líder que saiu dela deixa
    /// de liderar), ou abandonada.
    pub fn finish_change(&mut self, now: Instant, term: u64, committed: bool) -> Vec<Action> {
        if self.state != State::Leader || term != self.hard.term {
            return Vec::new();
        }
        match self.pending.take() {
            Some(next) if committed => self.set_config(next, now),
            _ => Vec::new(),
        }
    }

    /// Configuração em vigor: a mais recente gravada nos dados deste nó (no
    /// líder, os dados só a mostram depois de confirmada). Um líder fora dela
    /// deixa de liderar.
    pub fn set_config(&mut self, config: Membership, now: Instant) -> Vec<Action> {
        if config == self.config {
            return Vec::new();
        }
        self.config = config;
        if self.state != State::Leader {
            return Vec::new();
        }
        if !self.is_member() {
            self.become_follower(now);
            return vec![Action::StepDown];
        }
        // Membro novo ganha a carência de um timeout para responder.
        for &id in self.config.members.keys() {
            if id != self.id {
                self.contact.entry(id).or_insert(now);
            }
        }
        Vec::new()
    }

    fn lead(&mut self, now: Instant) -> Vec<Action> {
        let window = self.timing.election_min;
        let recent = |at: &Instant| now.saturating_duration_since(*at) <= window;
        let alive = self
            .config
            .members
            .keys()
            .filter(|&&id| id != self.id && self.contact.get(&id).is_some_and(recent))
            .count();
        if alive + usize::from(self.is_member()) < self.majority() {
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

    /// Envia `msg` aos membros e, durante uma troca, ao nó que está entrando.
    fn broadcast(&self, msg: Message) -> Vec<Action> {
        let mut peers: BTreeSet<NodeId> = self.config.members.keys().copied().collect();
        if let Some(next) = &self.pending {
            peers.extend(next.members.keys().copied());
        }
        peers.remove(&self.id);
        let send = |to| Action::Send { to, msg };
        peers.into_iter().map(send).collect()
    }

    /// Pré-votação vencida (ou nó único): candidatura de verdade, com termo + 1.
    fn campaign(&mut self, now: Instant) -> Vec<Action> {
        self.hard = HardState {
            term: self.hard.term + 1,
            voted_for: Some(self.id),
        };
        self.state = State::Candidate;
        self.votes = BTreeSet::from([self.id]);
        self.reset_election(now);
        if self.votes.len() >= self.majority() {
            return self.become_leader(now);
        }
        let request = Message::RequestVote {
            term: self.hard.term,
            candidate: self.id,
            last: self.last,
        };
        self.broadcast(request)
    }

    fn become_leader(&mut self, now: Instant) -> Vec<Action> {
        self.state = State::Leader;
        self.leader = Some(self.id);
        self.votes.clear();
        self.pending = None;
        // Carência de um timeout para os pares responderem ao primeiro batimento.
        let me = self.id;
        let peers = self.config.members.keys().filter(|&&id| id != me);
        self.contact = peers.map(|&id| (id, now)).collect();
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
        self.pending = None;
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
            Message::PreVote {
                term,
                candidate,
                last,
            } => (5, term, candidate, last, false),
            Message::PreVoteReply {
                term,
                voter,
                granted,
            } => (6, term, voter, none, granted),
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
            (5, 0) => Message::PreVote {
                term,
                candidate: id,
                last,
            },
            (6, flag @ 0..=1) => Message::PreVoteReply {
                term,
                voter: id,
                granted: flag == 1,
            },
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

    fn membership(ids: &[NodeId]) -> Membership {
        let members = ids.iter().map(|&id| (id, format!("n{id}"))).collect();
        Membership { index: 0, members }
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

    fn pre_granted(out: &[Action]) -> bool {
        matches!(reply_of(out), Message::PreVoteReply { granted: true, .. })
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
            let all: Vec<NodeId> = (1..=n).collect();
            Self::with_members(n, &all, seed)
        }

        /// `n` nós no ar, mas só `members` na configuração inicial de todos.
        fn with_members(n: u64, members: &[NodeId], seed: u64) -> Self {
            let now = Instant::now();
            let nodes = (1..=n)
                .map(|id| {
                    let (config, hard) = (membership(members), HardState::default());
                    Node::new(id, config, hard, timing(seed * 31 + id), now)
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

        fn node_mut(&mut self, id: NodeId) -> &mut Node {
            &mut self.nodes[id as usize - 1]
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

        /// Escrita do líder que a replicação leva a `to`: a posição de todos eles
        /// avança e, sendo um registro de configuração, ela passa a valer em cada
        /// seguidor. No líder, só vale em [`Sim::commit`] (os dados dele só a
        /// mostram depois de confirmada).
        fn write(&mut self, leader: NodeId, to: &[NodeId], config: Option<&Membership>) {
            let term = self.node(leader).term();
            let lsn = self.logs[leader as usize - 1].map_or(0, |p| p.lsn) + 1;
            let pos = Some(LogPos { epoch: term, lsn });
            self.logs[leader as usize - 1] = pos;
            for &id in to.iter().filter(|&&id| id != leader) {
                self.logs[id as usize - 1] = pos;
                if let Some(config) = config {
                    let now = self.now;
                    let out = self.node_mut(id).set_config(config.clone(), now);
                    self.apply(id, out, None);
                }
            }
        }

        /// O líder fica sabendo se a troca proposta foi confirmada.
        fn commit(&mut self, leader: NodeId, committed: bool) {
            let (now, term) = (self.now, self.node(leader).term());
            let out = self.node_mut(leader).finish_change(now, term, committed);
            self.apply(leader, out, None);
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
    fn vote_compares_epoch_before_lsn_and_a_node_without_position_never_votes() {
        let now = Instant::now();
        let config = membership(&[1, 2, 3]);
        let mut node = Node::new(3, config, HardState::default(), timing(7), now);
        let old_big = LogPos { epoch: 1, lsn: 99 };
        let new_small = LogPos { epoch: 2, lsn: 1 };
        let out = node.on_request_vote(now, 1, 1, old_big, Some(new_small));
        assert!(!granted(&out), "época menor perde mesmo com LSN maior");
        let out = node.on_request_vote(now, 2, 2, new_small, Some(old_big));
        assert!(granted(&out));
        let out = node.on_request_vote(now, 3, 1, new_small, None);
        assert!(!granted(&out), "sem posição não vota");
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
        // 1 e 2 vencem a pré-votação no mesmo instante; 3 ouve o 1 primeiro e 4, o 2.
        sim.now += Duration::from_secs(1);
        let now = sim.now;
        let pre = sim.nodes[0].on_timeout(now, Some(START));
        sim.nodes[1].on_timeout(now, Some(START));
        let first = sent_to(&pre, 3);
        assert!(matches!(first, Message::PreVote { term: 1, .. }));
        assert_eq!(sim.node(1).term(), 0, "a pré-votação não sobe o termo");
        let yes = |voter| Message::PreVoteReply {
            term: 1,
            voter,
            granted: true,
        };
        sim.nodes[0].on_message(now, yes(3), None);
        let a = sim.nodes[0].on_message(now, yes(4), None);
        sim.nodes[1].on_message(now, yes(3), None);
        let b = sim.nodes[1].on_message(now, yes(4), None);
        let split = sim.node(1).term();
        assert_eq!(split, 1);
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
    fn isolated_node_does_not_raise_its_term_nor_force_an_election_on_return() {
        for seed in 1..=10 {
            let mut sim = Sim::new(3, seed);
            sim.run(Duration::from_secs(2));
            let leader = sim.current_leaders()[0];
            let term = sim.node(leader).term();
            let lonely = (1..=3).find(|&id| id != leader).unwrap();
            sim.isolate(&[lonely]);
            sim.run(Duration::from_secs(3));
            // A pré-votação nunca vence isolada, então o termo não sobe.
            assert_eq!(sim.node(lonely).term(), term, "seed={seed}");
            sim.cut.clear();
            sim.run(Duration::from_secs(2));
            assert_eq!(sim.current_leaders(), vec![leader], "seed={seed}");
            assert_eq!(sim.node(leader).term(), term, "nenhuma eleição forçada");
            assert_eq!(sim.node(lonely).leader(), Some(leader));
        }
    }

    #[test]
    fn pre_vote_is_refused_while_a_leader_is_heard_and_never_changes_the_voter() {
        let now = Instant::now();
        let config = membership(&[1, 2, 3]);
        let mut node = Node::new(3, config, HardState::default(), timing(9), now);
        node.on_heartbeat(now, 4, 1);
        let soon = now + Duration::from_millis(50);
        let out = node.on_pre_vote(soon, 5, START, Some(START));
        assert!(!pre_granted(&out), "o líder segue vivo");
        let late = now + Duration::from_secs(1);
        let out = node.on_pre_vote(late, 5, START, Some(START));
        assert!(pre_granted(&out));
        let out = node.on_pre_vote(late, 4, START, Some(START));
        assert!(!pre_granted(&out), "termo pedido não é maior");
        assert_eq!((node.term(), node.hard_state().voted_for), (4, None));
        assert_eq!(node.leader(), Some(1));
    }

    #[test]
    fn adding_a_fourth_node_changes_the_majority() {
        for seed in 1..=10 {
            // O nó 4 já roda, mas fora da configuração: não se candidata.
            let mut sim = Sim::with_members(4, &[1, 2, 3], seed);
            sim.run(Duration::from_secs(2));
            let leaders = sim.current_leaders();
            assert_eq!(leaders.len(), 1, "seed={seed}");
            let leader = leaders[0];
            assert_ne!(leader, 4);
            assert_eq!(sim.node(4).term(), 0, "fora da configuração");
            let add = Change::Add(4, "n4".into());
            let next = sim.node_mut(leader).propose(&add).unwrap();
            assert_eq!((next.index, next.members.len()), (1, 4));
            let again = sim.node_mut(leader).propose(&Change::Remove(1));
            assert!(again.is_err(), "uma troca por vez");
            // Durante a troca, o líder já manda batimentos ao nó que está entrando.
            sim.run(Duration::from_millis(300));
            assert_eq!(sim.node(4).leader(), Some(leader), "seed={seed}");
            sim.write(leader, &[1, 2, 3, 4], Some(&next));
            sim.commit(leader, true);
            for id in 1..=4 {
                assert_eq!(sim.node(id).majority(), 3);
                assert!(sim.node(id).is_member());
            }
            // Com quatro membros, dois de cada lado não elegem ninguém (antes,
            // dois de três bastavam).
            let other = (1..=3).find(|&id| id != leader).unwrap();
            sim.isolate(&[leader, other]);
            let elected = sim.leaders.len();
            sim.run(Duration::from_secs(2));
            assert!(sim.current_leaders().is_empty(), "seed={seed}");
            assert_eq!(sim.leaders.len(), elected, "seed={seed}");
            sim.cut.clear();
            sim.run(Duration::from_secs(3));
            assert_eq!(sim.current_leaders().len(), 1, "seed={seed}");
        }
    }

    #[test]
    fn removed_node_never_campaigns_and_does_not_count() {
        for seed in 1..=10 {
            let mut sim = Sim::new(3, seed);
            sim.run(Duration::from_secs(2));
            let leader = sim.current_leaders()[0];
            let gone = (1..=3).find(|&id| id != leader).unwrap();
            let remove = Change::Remove(gone);
            let next = sim.node_mut(leader).propose(&remove).unwrap();
            sim.write(leader, &[1, 2, 3], Some(&next));
            sim.commit(leader, true);
            assert!(!sim.node(gone).is_member());
            assert_eq!(sim.node(leader).majority(), 2);
            let term = sim.node(gone).term();
            sim.run(Duration::from_secs(2));
            // O líder segue sem mandar batimentos ao removido, que não se candidata.
            assert_eq!(sim.current_leaders(), vec![leader], "seed={seed}");
            assert_eq!(sim.node(gone).term(), term);
            assert_eq!(sim.node(gone).leader(), None);
            // Sem o líder, o membro que sobrou não se elege sozinho: o removido
            // não conta.
            sim.isolate(&[leader]);
            let elected = sim.leaders.len();
            sim.run(Duration::from_secs(2));
            assert!(sim.current_leaders().is_empty(), "seed={seed}");
            assert_eq!(sim.leaders.len(), elected);
        }
    }

    #[test]
    fn leader_that_removes_itself_steps_down_only_after_the_commit() {
        for seed in 1..=10 {
            let mut sim = Sim::new(3, seed);
            sim.run(Duration::from_secs(2));
            let old = sim.current_leaders()[0];
            let term = sim.node(old).term();
            let remove = Change::Remove(old);
            let next = sim.node_mut(old).propose(&remove).unwrap();
            sim.write(old, &[1, 2, 3], Some(&next));
            // Os outros já usam a configuração nova; o líder segue até a confirmação.
            sim.run(Duration::from_millis(100));
            assert_eq!(sim.node(old).state(), State::Leader, "seed={seed}");
            sim.commit(old, true);
            assert_eq!(sim.node(old).state(), State::Follower);
            assert!(!sim.node(old).is_member());
            sim.run(Duration::from_secs(2));
            let leaders = sim.current_leaders();
            assert_eq!(leaders.len(), 1, "seed={seed}");
            assert_ne!(leaders[0], old);
            assert!(sim.node(leaders[0]).term() > term);
            assert!(sim.leaders.range(term + 1..).all(|(_, &id)| id != old));
        }
    }

    #[test]
    fn only_the_leader_changes_members_and_only_one_change_at_a_time() {
        let mut sim = Sim::new(3, 5);
        sim.run(Duration::from_secs(2));
        let leader = sim.current_leaders()[0];
        let follower = (1..=3).find(|&id| id != leader).unwrap();
        let refused = sim.node_mut(follower).propose(&Change::Remove(leader));
        assert!(refused.is_err(), "seguidor não troca membros");
        let node = sim.node_mut(leader);
        let member = Change::Add(3, "x".into());
        assert!(node.propose(&member).is_err(), "já é membro");
        let spaces = Change::Add(9, "a b".into());
        assert!(node.propose(&spaces).is_err(), "endereço inválido");
        assert!(node.propose(&Change::Remove(7)).is_err(), "não é membro");
        node.propose(&Change::Add(4, "n4".into())).unwrap();
        let second = Change::Remove(follower);
        assert!(node.propose(&second).is_err(), "concorrente");
        sim.commit(leader, false);
        assert_eq!(sim.node(leader).config().members.len(), 3, "abandonada");
        assert_eq!(sim.node(leader).pending(), None);
        let next = sim.node_mut(leader).propose(&second).unwrap();
        assert_eq!((next.index, next.members.len()), (1, 2));
    }

    #[test]
    fn persisted_vote_is_not_given_twice_in_the_same_term_after_restart() {
        let name = format!("minidb-raft-unit-{}", std::process::id());
        let dir = std::env::temp_dir().join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (now, pos) = (Instant::now(), Some(START));
        let config = membership(&[1, 2, 3]);
        assert_eq!(load_hard_state(&dir).unwrap(), HardState::default());
        let mut node = Node::new(3, config.clone(), HardState::default(), timing(1), now);
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
        let mut node = Node::new(3, config, hard, timing(1), now);
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
            Message::PreVote {
                term: 8,
                candidate: 2,
                last,
            },
            Message::PreVoteReply {
                term: 8,
                voter: 1,
                granted: true,
            },
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
        let add = Change::Add(9, "c@d:3".into());
        let config = membership(&[1, 4]).with(&add).unwrap();
        assert_eq!(config.encode(), "1 1@n1,4@n4,9@c@d:3");
        assert_eq!(Membership::decode(&config.encode()).unwrap(), config);
        for bad in ["", "7", "x 1@a", "7 ", "7 0@a"] {
            assert!(Membership::decode(bad).is_err(), "{bad:?}");
        }
    }
}
