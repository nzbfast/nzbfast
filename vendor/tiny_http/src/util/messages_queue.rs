use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

enum Control<T> {
    Elem(T),
    Unblock,
}

pub struct MessagesQueue<T>
where
    T: Send,
{
    queue: Mutex<VecDeque<Control<T>>>,
    /// Signalled when something is added.
    has_item: Condvar,
    /// nzbfast patch 11 (see VENDORING.md): signalled when something is taken,
    /// so a blocked producer can proceed.
    has_room: Condvar,
    /// nzbfast patch 11: the hard bound `with_capacity` never was.
    bound: usize,
}

impl<T> MessagesQueue<T>
where
    T: Send,
{
    /// nzbfast patch 11 (see VENDORING.md): `capacity` is now a HARD BOUND, not
    /// a `VecDeque` pre-allocation hint.
    ///
    /// Upstream's name was the whole bug: `with_capacity(8)` reads like a
    /// bounded queue and is not one - `push` never blocks and the deque simply
    /// grows. On a plain connection the parser pushed every pipelined request
    /// without waiting for the previous response, so one peer that sends request
    /// lines and never reads a response turned modest request bytes into
    /// heap-backed `Request` objects, headers, channels and writer state until
    /// the allocator gave up and aborted the daemon.
    ///
    /// Patch 12's one-outstanding-request rule already holds this below the
    /// connection ceiling by construction; the bound is the structural guarantee
    /// underneath it, so a future caller that pushes without backpressure blocks
    /// rather than growing without limit.
    pub fn with_capacity(capacity: usize) -> Arc<MessagesQueue<T>> {
        let bound = capacity.max(1);
        Arc::new(MessagesQueue {
            queue: Mutex::new(VecDeque::with_capacity(bound.min(64))),
            has_item: Condvar::new(),
            has_room: Condvar::new(),
            bound,
        })
    }

    /// Pushes an element to the queue, waiting while the queue is at its bound.
    pub fn push(&self, value: T) {
        let mut queue = self.queue.lock().unwrap();
        while queue.len() >= self.bound {
            queue = self.has_room.wait(queue).unwrap();
        }
        queue.push_back(Control::Elem(value));
        self.has_item.notify_one();
    }

    /// Pushes an element without waiting for room.
    ///
    /// For the control messages that must never block: the accept thread's
    /// terminal error (it is about to exit, and blocking it would leave
    /// consumers waiting on a queue with no producer at all) and `unblock`,
    /// whose whole job is to get a parked consumer moving.
    pub fn push_control(&self, value: T) {
        let mut queue = self.queue.lock().unwrap();
        queue.push_back(Control::Elem(value));
        self.has_item.notify_one();
    }

    /// Unblock one thread stuck in pop loop.
    pub fn unblock(&self) {
        let mut queue = self.queue.lock().unwrap();
        queue.push_back(Control::Unblock);
        self.has_item.notify_one();
    }

    /// Pops an element. Blocks until one is available.
    /// Returns None in case unblock() was issued.
    pub fn pop(&self) -> Option<T> {
        let mut queue = self.queue.lock().unwrap();

        loop {
            match queue.pop_front() {
                Some(Control::Elem(value)) => {
                    self.has_room.notify_one();
                    return Some(value);
                }
                Some(Control::Unblock) => {
                    self.has_room.notify_one();
                    return None;
                }
                None => (),
            }

            queue = self.has_item.wait(queue).unwrap();
        }
    }

    /// Tries to pop an element without blocking.
    pub fn try_pop(&self) -> Option<T> {
        let mut queue = self.queue.lock().unwrap();
        match queue.pop_front() {
            Some(Control::Elem(value)) => {
                self.has_room.notify_one();
                Some(value)
            }
            Some(Control::Unblock) => {
                self.has_room.notify_one();
                None
            }
            None => None,
        }
    }

    /// Tries to pop an element without blocking
    /// more than the specified timeout duration
    /// or unblock() was issued
    pub fn pop_timeout(&self, timeout: Duration) -> Option<T> {
        let mut queue = self.queue.lock().unwrap();
        let mut duration = timeout;
        loop {
            match queue.pop_front() {
                Some(Control::Elem(value)) => {
                    self.has_room.notify_one();
                    return Some(value);
                }
                Some(Control::Unblock) => {
                    self.has_room.notify_one();
                    return None;
                }
                None => (),
            }
            let now = Instant::now();
            // nzbfast patch 14 (see VENDORING.md): wait for what is LEFT of
            // the timeout. Upstream passed the full `timeout` on every turn,
            // so a wakeup that found nothing (a spurious one, or an item
            // another popper took first) restarted the whole wait and the
            // call could block for nearly twice what it was given.
            let (_queue, result) = self.has_item.wait_timeout(queue, duration).unwrap();
            queue = _queue;
            let sleep_time = now.elapsed();
            duration = if duration > sleep_time {
                duration - sleep_time
            } else {
                Duration::from_millis(0)
            };
            if result.timed_out()
                || (duration.as_secs() == 0 && duration.subsec_nanos() < 1_000_000)
            {
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MessagesQueue;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// The bound is real: a producer with nobody consuming cannot grow the
    /// queue past it. Upstream this loop would have queued all 500.
    #[test]
    fn push_blocks_at_the_bound_instead_of_growing() {
        let q = MessagesQueue::<usize>::with_capacity(4);
        let pushed = Arc::new(AtomicUsize::new(0));

        let producer = {
            let q = q.clone();
            let pushed = pushed.clone();
            std::thread::spawn(move || {
                for i in 0..500 {
                    q.push(i);
                    pushed.fetch_add(1, Ordering::AcqRel);
                }
            })
        };

        // Give the producer every chance to run away with it.
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            pushed.load(Ordering::Acquire) <= 4,
            "producer got {} items ahead of a bound of 4",
            pushed.load(Ordering::Acquire)
        );

        // Draining releases it, and nothing is lost.
        for expect in 0..500 {
            assert_eq!(q.pop(), Some(expect));
        }
        producer.join().unwrap();
    }

    /// nzbfast patch 14: a wakeup that finds nothing must not restart the
    /// wait. One empty wakeup lands at 300 ms of a 400 ms timeout; the call
    /// must still return at ~400 ms. NEGATIVE CONTROL, run: passing
    /// `timeout` instead of `duration` to `wait_timeout` makes it ~700 ms.
    /// The bound is 600 ms - 200 ms of slack over the right answer and
    /// 100 ms under the wrong one - so a loaded box can at worst make the
    /// fixed code look slow, never the defect look fixed.
    #[test]
    fn an_empty_wakeup_does_not_restart_the_timeout() {
        let q = MessagesQueue::<usize>::with_capacity(4);
        let waker = {
            let q = q.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                // Take the lock so the wake lands while the popper waits,
                // not before it has started.
                let _held = q.queue.lock().unwrap();
                q.has_item.notify_all();
            })
        };
        let t0 = std::time::Instant::now();
        assert_eq!(q.pop_timeout(Duration::from_millis(400)), None);
        let took = t0.elapsed();
        waker.join().unwrap();
        assert!(
            took >= Duration::from_millis(390),
            "returned early: {:?}",
            took
        );
        assert!(
            took < Duration::from_millis(600),
            "an empty wakeup restarted the wait: {:?} for a 400 ms timeout",
            took
        );
    }

    /// A control message must land even when the queue is full, or the accept
    /// thread's terminal error would deadlock against its own consumers.
    #[test]
    fn control_messages_bypass_the_bound() {
        let q = MessagesQueue::<usize>::with_capacity(2);
        q.push(1);
        q.push(2);
        q.push_control(99);
        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.pop(), Some(2));
        assert_eq!(q.pop(), Some(99));
    }
}
