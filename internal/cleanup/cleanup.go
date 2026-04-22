package cleanup

import (
	"context"
	"log"
	"time"

	"github.com/brightcolor/mailprobe/internal/store"
)

func Start(ctx context.Context, logger *log.Logger, st *store.Store, interval, retention time.Duration) {
	if logger == nil {
		logger = log.Default()
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				boxes, msgs, err := st.Cleanup(ctx, time.Now(), retention)
				if err != nil {
					logger.Printf("cleanup: error: %v", err)
					continue
				}
				if boxes > 0 || msgs > 0 {
					logger.Printf("cleanup: deleted mailboxes=%d messages=%d", boxes, msgs)
				}
			}
		}
	}()
}
