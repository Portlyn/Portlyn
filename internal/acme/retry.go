package acme

import (
	"time"

	"portlyn/internal/domain"
)

const (
	retryBaseDelay     = 5 * time.Minute
	retryMaxDelay      = 24 * time.Hour
	renewedRecheckWait = time.Hour
)

func retryDelay(failures int) time.Duration {
	delay := retryBaseDelay
	for i := 1; i < failures; i++ {
		delay *= 2
		if delay >= retryMaxDelay {
			return retryMaxDelay
		}
	}
	return delay
}

func nextRetryState(item *domain.Certificate, now time.Time, renewWithin time.Duration) (int, *time.Time) {
	if item.Status == domain.CertificateStatusFailed {
		failures := item.FailureCount + 1
		next := now.Add(retryDelay(failures)).UTC()
		return failures, &next
	}
	if !item.ExpiresAt.IsZero() && item.ExpiresAt.Before(now.Add(renewWithin)) {
		next := now.Add(renewedRecheckWait).UTC()
		return 0, &next
	}
	return 0, nil
}
