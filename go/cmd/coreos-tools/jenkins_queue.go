package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// QueueItemDisplay is a formatted queue item for display.
type QueueItemDisplay struct {
	ID           int       `json:"id"`
	JobName      string    `json:"job_name"`
	JobURL       string    `json:"job_url"`
	InQueueSince time.Time `json:"in_queue_since"`
	Blocked      bool      `json:"blocked"`
	Buildable    bool      `json:"buildable"`
	Stuck        bool      `json:"stuck"`
	Why          string    `json:"why,omitempty"`
	Params       string    `json:"params,omitempty"`
}

// queue list
var queueListCmd = &cobra.Command{
	Use:   "list",
	Short: "List items in the build queue",
	Long:  `List all items currently waiting in the Jenkins build queue.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		queue, err := jenkinsClient.GetQueue()
		if err != nil {
			printError(err)
			return err
		}

		// Format queue items for display
		var items []QueueItemDisplay
		for _, item := range queue.Items {
			items = append(items, QueueItemDisplay{
				ID:           item.ID,
				JobName:      item.Task.Name,
				JobURL:       item.Task.URL,
				InQueueSince: time.UnixMilli(item.InQueueSince),
				Blocked:      item.Blocked,
				Buildable:    item.Buildable,
				Stuck:        item.Stuck,
				Why:          item.Why,
				Params:       item.Params,
			})
		}

		return printJSON(items)
	},
}

// queue cancel
var queueCancelCmd = &cobra.Command{
	Use:   "cancel <queue-id>",
	Short: "Cancel a queued build",
	Long:  `Cancel a build waiting in the queue by its queue ID.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var queueID int
		if _, err := fmt.Sscanf(args[0], "%d", &queueID); err != nil {
			return fmt.Errorf("invalid queue ID: %s", args[0])
		}

		err := jenkinsClient.CancelQueueItem(queueID)
		if err != nil {
			printError(err)
			return err
		}

		result := map[string]interface{}{
			"status":   "cancelled",
			"queue_id": queueID,
			"message":  fmt.Sprintf("Queue item %d cancelled", queueID),
		}
		return printJSON(result)
	},
}

func init() {
	// Add commands to queue group
	jenkinsQueueCmd.AddCommand(queueListCmd)
	jenkinsQueueCmd.AddCommand(queueCancelCmd)

	// Suppress usage on errors
	queueListCmd.SilenceUsage = true
	queueCancelCmd.SilenceUsage = true
}
