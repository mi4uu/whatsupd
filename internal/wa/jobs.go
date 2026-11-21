package wa

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/appstate"
	waBinary "go.mau.fi/whatsmeow/binary"
)

// jobQueue runs background jobs one at a time, de-duplicated by key.
type jobQueue struct {
	mu      sync.Mutex
	pending map[string]bool
	ch      chan job
}

type job struct {
	key string
	fn  func(context.Context) error
}

func newJobQueue() *jobQueue {
	return &jobQueue{pending: map[string]bool{}, ch: make(chan job, 1024)}
}

// add schedules fn unless a job with the same key is already waiting.
func (q *jobQueue) add(key string, fn func(context.Context) error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.pending[key] {
		return
	}
	select {
	case q.ch <- job{key, fn}:
		q.pending[key] = true
	default: // queue full; the periodic refresh will catch up
	}
}

func (q *jobQueue) run(ctx context.Context, log *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-q.ch:
			q.mu.Lock()
			delete(q.pending, j.key)
			q.mu.Unlock()
			if err := j.fn(ctx); err != nil && ctx.Err() == nil {
				log.Warn("background job failed", "job", j.key, "err", err)
			}
		}
	}
}

// heartbeat persists the status, remembers when the daemon was last online
// and refreshes groups and contacts periodically.
func (m *Manager) heartbeat(ctx context.Context) {
	minute := time.NewTicker(time.Minute)
	defer minute.Stop()
	reconcile := time.NewTicker(30 * time.Minute)
	defer reconcile.Stop()
	refresh := time.NewTicker(6 * time.Hour)
	defer refresh.Stop()
	media := time.NewTicker(10 * time.Minute)
	defer media.Stop()
	var downSince time.Time
	threshold := 3 * time.Minute
	for {
		select {
		case <-ctx.Done():
			return
		case <-media.C:
			if m.cfg.AutoMedia {
				m.sweepMedia(ctx)
			}
		case <-minute.C:
			m.markOnline()
			m.persistStatus()
			// Watchdog: whatsmeow stops reconnecting after some failures (stream
			// replaced, most connect failures). Rebuild the connection when a
			// paired device stays disconnected, backing off on repeats.
			cli := m.Client()
			switch {
			case cli == nil || cli.Store.ID == nil:
				downSince = time.Time{}
			case cli.IsConnected():
				downSince, threshold = time.Time{}, 3*time.Minute
			case downSince.IsZero():
				downSince = time.Now()
			case time.Since(downSince) >= threshold:
				downSince = time.Time{}
				threshold = min(threshold*2, 30*time.Minute)
				m.signalRestart("reconnect")
			}
		case <-reconcile.C:
			m.jobs.add("reconcile", m.reconcile)
		case <-refresh.C:
			m.jobs.add("groups", m.refreshGroups)
			m.jobs.add("contacts", m.refreshContacts)
			m.jobs.add("appstate", m.syncAppState)
		}
	}
}

func (m *Manager) refreshGroups(ctx context.Context) error {
	cli := m.Client()
	if cli == nil || !cli.IsLoggedIn() {
		return nil
	}
	groups, err := cli.GetJoinedGroups(ctx)
	if err != nil {
		return err
	}
	if err := m.ing.Groups(ctx, groups, true); err != nil {
		return err
	}
	m.log.Info("groups refreshed", "count", len(groups))
	m.bus.Publish(Event{Type: "sync"})
	return nil
}

func (m *Manager) refreshContacts(ctx context.Context) error {
	cli := m.Client()
	if cli == nil || cli.Store.ID == nil {
		return nil
	}
	all, err := cli.Store.Contacts.GetAllContacts(ctx)
	if err != nil {
		return err
	}
	return m.ing.Contacts(ctx, all)
}

// syncAppState pulls chat state (archived, pinned, muted, read, contacts) that the phone changed.
// whatsmeow only logs an LTHash mismatch and then stays stuck on that patch forever, so every later
// change from the phone is lost; a full sync from the server snapshot is the way out.
func (m *Manager) syncAppState(ctx context.Context) error {
	cli := m.Client()
	if cli == nil || cli.Store.ID == nil {
		return nil
	}
	var first error
	for _, name := range appstate.AllPatchNames {
		err := cli.FetchAppState(ctx, name, false, false)
		if errors.Is(err, appstate.ErrMismatchingLTHash) {
			m.log.Warn("app state is out of step with the server, syncing it from scratch", "name", name)
			err = cli.FetchAppState(ctx, name, true, false)
		}
		if errors.Is(err, appstate.ErrMismatchingLTHash) {
			// The server's own snapshot does not verify either. The phone holds the truth: ask it
			// for a recovery snapshot; whatsmeow applies the answer when the phone is next online.
			m.log.Warn("server snapshot of app state does not verify, asking the phone for a recovery copy", "name", name)
			_, err = cli.SendPeerMessage(ctx, whatsmeow.BuildAppStateRecoveryRequest(name))
		}
		if err != nil && first == nil {
			first = err
		}
	}
	m.bus.Publish(Event{Type: "sync"})
	return first
}

func (m *Manager) reconcile(ctx context.Context) error {
	n, err := m.ing.Reconcile(ctx)
	if n > 0 {
		m.log.Info("merged hidden-number (LID) identities into phone numbers", "count", n)
		m.bus.Publish(Event{Type: "sync"})
	}
	return err
}

func hasChild(n *waBinary.Node, tag string) bool {
	if n == nil {
		return false
	}
	for _, c := range n.GetChildren() {
		if c.Tag == tag {
			return true
		}
	}
	return false
}

// mediaWorker downloads media of new messages (--auto-media) off the event loop.
func (m *Manager) mediaWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-m.mediaQueue:
			if _, err := m.DownloadMedia(ctx, job[0], job[1]); err != nil && ctx.Err() == nil {
				m.log.Debug("auto media download", "chat", job[0], "id", job[1], "err", err)
			}
		}
	}
}

// sweepMedia re-queues recent live media that was never downloaded (for
// example because the queue was full).
func (m *Manager) sweepMedia(ctx context.Context) {
	pending, err := m.arc.PendingMedia(ctx, time.Now().Add(-7*24*time.Hour).Unix(), m.cfg.MediaMaxBytes, 500)
	if err != nil {
		m.log.Warn("media sweep", "err", err)
		return
	}
	for _, p := range pending {
		select {
		case m.mediaQueue <- p:
		default:
			return
		}
	}
}
