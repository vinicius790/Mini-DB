//! Eventos do banco: mudanças de linhas confirmadas (change stream) e
//! notificações `NOTIFY`/`LISTEN`.
//!
//! O barramento é compartilhado por todos os handles do mesmo banco. Mudanças
//! ficam num anel em memória com capacidade limitada (o consumidor retoma pelo
//! LSN; se ficou para trás demais, recebe [`ChangeError::TooOld`] e relê as
//! tabelas). Notificações são entregues às sessões que escutam o canal, na
//! ordem do commit.

use crate::rel::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    Insert,
    Update,
    Delete,
}

impl ChangeKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }
}

/// Uma linha alterada por um commit.
#[derive(Clone, Debug, PartialEq)]
pub struct Change {
    pub lsn: u64,
    pub table: String,
    pub kind: ChangeKind,
    pub columns: Vec<String>,
    pub old: Option<Vec<Value>>,
    pub new: Option<Vec<Value>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    pub lsn: u64,
    pub channel: String,
    pub payload: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChangeError {
    /// O LSN pedido já saiu do anel; o primeiro disponível vai junto.
    TooOld { first_available: u64 },
}

#[derive(Default)]
struct Listener {
    channels: HashSet<String>,
    queue: VecDeque<Notification>,
}

struct State {
    changes: VecDeque<Change>,
    capacity: usize,
    /// Maior LSN publicado (mesmo sem mudanças relacionais).
    head_lsn: u64,
    /// Menor LSN já descartado do anel (0 = nada descartado).
    dropped_until: u64,
    listeners: HashMap<u64, Listener>,
    next_listener: u64,
}

pub struct EventBus {
    state: Mutex<State>,
    cv: Condvar,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(10_000)
    }
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(State {
                changes: VecDeque::new(),
                capacity: capacity.max(1),
                head_lsn: 0,
                dropped_until: 0,
                listeners: HashMap::new(),
                next_listener: 1,
            }),
            cv: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_capacity(&self, capacity: usize) {
        let mut st = self.lock();
        st.capacity = capacity.max(1);
        while st.changes.len() > st.capacity {
            if let Some(c) = st.changes.pop_front() {
                st.dropped_until = c.lsn;
            }
        }
    }

    /// Publica as mudanças e notificações de um commit já durável.
    pub fn publish(&self, lsn: u64, changes: Vec<Change>, notifications: Vec<(String, String)>) {
        let mut st = self.lock();
        st.head_lsn = st.head_lsn.max(lsn);
        for mut c in changes {
            c.lsn = lsn;
            if st.changes.len() >= st.capacity {
                if let Some(old) = st.changes.pop_front() {
                    st.dropped_until = old.lsn;
                }
            }
            st.changes.push_back(c);
        }
        for (channel, payload) in notifications {
            let n = Notification {
                lsn,
                channel,
                payload,
            };
            for l in st.listeners.values_mut() {
                if l.channels.contains(&n.channel) {
                    l.queue.push_back(n.clone());
                    if l.queue.len() > 10_000 {
                        l.queue.pop_front();
                    }
                }
            }
        }
        self.cv.notify_all();
    }

    pub fn head_lsn(&self) -> u64 {
        self.lock().head_lsn
    }

    /// Mudanças com LSN maior que `since`, cerca de `limit` (o lote vai até o fim do
    /// último commit, para nunca cortá-lo); espera até `timeout` se ainda não há nenhuma.
    pub fn changes_since(
        &self,
        since: u64,
        limit: usize,
        timeout: Duration,
    ) -> Result<Vec<Change>, ChangeError> {
        let deadline = Instant::now() + timeout;
        let mut st = self.lock();
        loop {
            if since < st.dropped_until {
                return Err(ChangeError::TooOld {
                    first_available: st.dropped_until,
                });
            }
            let mut out: Vec<Change> = st
                .changes
                .iter()
                .filter(|c| c.lsn > since)
                .take(limit.max(1))
                .cloned()
                .collect();
            // Nunca corta um commit no meio: quem retoma por `lsn > since` perderia o resto.
            if let Some(last) = out.last().map(|c| c.lsn) {
                let seen = out.iter().filter(|c| c.lsn == last).count();
                let rest: Vec<Change> = st
                    .changes
                    .iter()
                    .filter(|c| c.lsn == last)
                    .skip(seen)
                    .cloned()
                    .collect();
                out.extend(rest);
            }
            if !out.is_empty() {
                return Ok(out);
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(Vec::new());
            }
            st = self
                .cv
                .wait_timeout(st, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    pub fn subscribe(&self) -> u64 {
        let mut st = self.lock();
        let id = st.next_listener;
        st.next_listener += 1;
        st.listeners.insert(id, Listener::default());
        id
    }

    pub fn unsubscribe(&self, id: u64) {
        self.lock().listeners.remove(&id);
    }

    pub fn listen(&self, id: u64, channel: &str) {
        if let Some(l) = self.lock().listeners.get_mut(&id) {
            l.channels.insert(channel.to_string());
        }
    }

    /// `None` = todos os canais.
    pub fn unlisten(&self, id: u64, channel: Option<&str>) {
        if let Some(l) = self.lock().listeners.get_mut(&id) {
            match channel {
                Some(c) => {
                    l.channels.remove(c);
                }
                None => l.channels.clear(),
            }
        }
    }

    pub fn channels(&self, id: u64) -> Vec<String> {
        let st = self.lock();
        let mut out: Vec<String> = st
            .listeners
            .get(&id)
            .map(|l| l.channels.iter().cloned().collect())
            .unwrap_or_default();
        out.sort();
        out
    }

    /// Notificações pendentes do ouvinte; espera até `timeout` se não há.
    pub fn poll(&self, id: u64, timeout: Duration) -> Vec<Notification> {
        let deadline = Instant::now() + timeout;
        let mut st = self.lock();
        loop {
            let pending: Vec<Notification> = match st.listeners.get_mut(&id) {
                Some(l) => l.queue.drain(..).collect(),
                None => return Vec::new(),
            };
            if !pending.is_empty() {
                return pending;
            }
            let now = Instant::now();
            if now >= deadline {
                return Vec::new();
            }
            st = self
                .cv
                .wait_timeout(st, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn change(table: &str) -> Change {
        Change {
            lsn: 0,
            table: table.into(),
            kind: ChangeKind::Insert,
            columns: vec!["id".into()],
            old: None,
            new: Some(vec![Value::Int(1)]),
        }
    }

    #[test]
    fn ring_buffer_drops_old_changes_and_reports_too_old() {
        let bus = EventBus::new(2);
        bus.publish(1, vec![change("a")], vec![]);
        bus.publish(2, vec![change("b")], vec![]);
        bus.publish(3, vec![change("c")], vec![]);
        assert_eq!(
            bus.changes_since(0, 10, Duration::ZERO),
            Err(ChangeError::TooOld { first_available: 1 })
        );
        let got = bus.changes_since(1, 10, Duration::ZERO).unwrap();
        assert_eq!(
            got.iter().map(|c| c.table.as_str()).collect::<Vec<_>>(),
            ["b", "c"]
        );
        assert!(bus.changes_since(3, 10, Duration::ZERO).unwrap().is_empty());
    }

    #[test]
    fn listeners_receive_only_their_channels_and_wake_up() {
        let bus = Arc::new(EventBus::default());
        let a = bus.subscribe();
        let b = bus.subscribe();
        bus.listen(a, "jogo");
        bus.listen(b, "chat");
        let waiter = {
            let bus = Arc::clone(&bus);
            thread::spawn(move || bus.poll(a, Duration::from_secs(5)))
        };
        thread::sleep(Duration::from_millis(30));
        bus.publish(
            7,
            vec![],
            vec![
                ("jogo".into(), "start".into()),
                ("chat".into(), "oi".into()),
            ],
        );
        let got = waiter.join().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(
            (got[0].channel.as_str(), got[0].payload.as_str(), got[0].lsn),
            ("jogo", "start", 7)
        );
        assert_eq!(bus.poll(b, Duration::ZERO)[0].payload, "oi");
        bus.unlisten(b, None);
        bus.publish(8, vec![], vec![("chat".into(), "x".into())]);
        assert!(bus.poll(b, Duration::ZERO).is_empty());
        bus.unsubscribe(a);
        assert!(bus.poll(a, Duration::ZERO).is_empty());
    }
}
