package repository

import (
	"errors"
	"time"

	"vulnark/internal/model"
)

// ValidateDirectVulnerabilityTransition prevents bypassing retest verification.
func ValidateDirectVulnerabilityTransition(oldStatus, newStatus string) error {
	if newStatus == model.StatusVerified {
		return errors.New("请通过复测接口验证漏洞")
	}
	if newStatus == model.StatusClosed && oldStatus != model.StatusVerified && oldStatus != model.StatusClosed {
		return errors.New("只有复测通过的漏洞可以关闭")
	}
	if (oldStatus == model.StatusVerified || oldStatus == model.StatusClosed) && newStatus != oldStatus && newStatus != model.StatusClosed {
		return errors.New("请通过失败复测重新打开漏洞")
	}
	return nil
}

// VulnerabilityLifecycleFields must be called with the latest locked row. The
// caller commits these SLA fields together with status, timeline and retest.
func VulnerabilityLifecycleFields(v *model.Vulnerability, newStatus string, now time.Time) map[string]interface{} {
	fields := map[string]interface{}{}
	if v.Status == newStatus {
		return fields
	}
	responseDue, fixDue := v.ResponseDueAt, v.FixDueAt
	terminal := newStatus == model.StatusFixed || newStatus == model.StatusVerified || newStatus == model.StatusClosed
	wasTerminal := v.Status == model.StatusFixed || v.Status == model.StatusVerified || v.Status == model.StatusClosed
	if v.PauseStartedAt != nil && terminal {
		duration := now.Sub(*v.PauseStartedAt)
		if duration < 0 {
			duration = 0
		}
		fields["paused_seconds"] = v.PausedSeconds + int64(duration/time.Second)
		fields["pause_started_at"] = nil
		fields["pause_ended_at"] = now
		if responseDue != nil && v.FirstResponseAt == nil {
			due := responseDue.Add(duration)
			responseDue = &due
			fields["response_due_at"] = due
		}
		if fixDue != nil {
			due := fixDue.Add(duration)
			fixDue = &due
			fields["fix_due_at"] = due
		}
	}
	if newStatus != model.StatusNew && v.FirstResponseAt == nil {
		fields["first_response_at"] = now
		if v.PauseStartedAt != nil && !terminal && responseDue != nil && now.After(*v.PauseStartedAt) {
			due := responseDue.Add(now.Sub(*v.PauseStartedAt))
			responseDue = &due
			fields["response_due_at"] = due
		}
		if responseDue != nil {
			fields["response_overdue"] = now.After(*responseDue)
		}
	}
	if terminal {
		if v.FixedAt == nil {
			fields["fixed_at"] = now
		}
		if fixDue != nil {
			completed := now
			if v.FixedAt != nil {
				completed = *v.FixedAt
			}
			fields["fix_overdue"] = completed.After(*fixDue)
		}
	}
	if wasTerminal && !terminal {
		// Verification time does not consume the fix budget. Preserve the
		// remaining (possibly negative) duration present when the fix was made.
		if v.FixedAt != nil && fixDue != nil && now.After(*v.FixedAt) {
			fields["fix_due_at"] = fixDue.Add(now.Sub(*v.FixedAt))
		}
		fields["fixed_at"] = nil
		fields["verified_at"] = nil
		fields["closed_at"] = nil
		fields["sla_cycle"] = v.SLACycle + 1
		fields["fix_overdue_level"] = 0
	}
	return fields
}
