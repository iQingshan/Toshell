package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"toshell/internal/operator/commands"
)

var (
	serverURL string
	apiKey    string
	username  string
	password  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "toshell-cli",
		Short: "ToShell C2 Framework CLI",
		Long:  "Command-line client for ToShell C2 Framework",
	}

	rootCmd.PersistentFlags().StringVar(&serverURL, "server", "http://localhost:8081", "Server URL")
	rootCmd.PersistentFlags().StringVar(&apiKey, "api-key", "", "API Key")

	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Login to the server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if username == "" {
				fmt.Print("Username: ")
				reader := bufio.NewReader(os.Stdin)
				username, _ = reader.ReadString('\n')
				username = strings.TrimSpace(username)
			}
			if password == "" {
				fmt.Print("Password: ")
				reader := bufio.NewReader(os.Stdin)
				password, _ = reader.ReadString('\n')
				password = strings.TrimSpace(password)
			}

			client := commands.NewClient(serverURL, apiKey, "", "")
			err := client.Login(username, password)
			if err != nil {
				return fmt.Errorf("login failed: %w", err)
			}

			fmt.Println("Login successful!")
			return nil
		},
	}
	loginCmd.Flags().StringVar(&username, "username", "", "Username")
	loginCmd.Flags().StringVar(&password, "password", "", "Password")

	sessionsCmd := &cobra.Command{
		Use:   "sessions",
		Short: "List sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := commands.NewClient(serverURL, apiKey, "", "")
			sessions, err := client.ListSessions()
			if err != nil {
				return fmt.Errorf("failed to list sessions: %w", err)
			}

			fmt.Printf("%-20s %-15s %-15s %-10s %-20s\n", "ID", "Hostname", "Username", "OS", "Last Seen")
			fmt.Println(strings.Repeat("-", 90))
			for _, s := range sessions {
				fmt.Printf("%-20s %-15s %-15s %-10s %-20s\n",
					s.ID[:16],
					s.Hostname,
					s.Username,
					s.OS,
					s.LastSeen.Format("2006-01-02 15:04:05"),
				)
			}

			return nil
		},
	}

	interactCmd := &cobra.Command{
		Use:   "interact <session_id> <command>",
		Short: "Interact with a session",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]
			command := strings.Join(args[1:], " ")

			client := commands.NewClient(serverURL, apiKey, "", "")
			taskID, err := client.InteractSession(sessionID, command, nil, "shell", 30)
			if err != nil {
				return fmt.Errorf("failed to send command: %w", err)
			}

			fmt.Printf("Task %d sent to session %s\n", taskID, sessionID)

			time.Sleep(2 * time.Second)

			task, err := client.GetTask(taskID)
			if err != nil {
				return fmt.Errorf("failed to get task result: %w", err)
			}

			fmt.Printf("Exit Code: %d\n", task.ExitCode)
			fmt.Printf("Output:\n%s\n", task.Output)
			if task.Error != "" {
				fmt.Printf("Error:\n%s\n", task.Error)
			}

			return nil
		},
	}

	listenersCmd := &cobra.Command{
		Use:   "listeners",
		Short: "List listeners",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := commands.NewClient(serverURL, apiKey, "", "")
			listeners, err := client.ListListeners()
			if err != nil {
				return fmt.Errorf("failed to list listeners: %w", err)
			}

			fmt.Printf("%-20s %-10s %-15s %-10s %-10s\n", "Name", "Type", "Address", "Port", "Status")
			fmt.Println(strings.Repeat("-", 70))
			for _, l := range listeners {
				fmt.Printf("%-20s %-10s %-15s %-10d %-10s\n",
					l.Name,
					l.Type,
					fmt.Sprintf("%s:%s", l.BindAddr, "8080"),
					l.BindPort,
					l.Status,
				)
			}

			return nil
		},
	}

	createListenerCmd := &cobra.Command{
		Use:   "create-listener <name> <type> <port>",
		Short: "Create a new listener",
		Args:  cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			ltype := args[1]
			var port uint16
			fmt.Sscanf(args[2], "%d", &port)

			client := commands.NewClient(serverURL, apiKey, "", "")
			listenerID, err := client.CreateListener(name, ltype, "0.0.0.0", port, "", "")
			if err != nil {
				return fmt.Errorf("failed to create listener: %w", err)
			}

			fmt.Printf("Listener %s created with ID: %s\n", name, listenerID)

			err = client.StartListener(listenerID)
			if err != nil {
				return fmt.Errorf("failed to start listener: %w", err)
			}

			fmt.Println("Listener started successfully")
			return nil
		},
	}

	tasksCmd := &cobra.Command{
		Use:   "tasks [session_id]",
		Short: "List tasks",
		RunE: func(cmd *cobra.Command, args []string) error {
			var sessionID string
			if len(args) > 0 {
				sessionID = args[0]
			}

			client := commands.NewClient(serverURL, apiKey, "", "")
			tasks, err := client.ListTasks(sessionID)
			if err != nil {
				return fmt.Errorf("failed to list tasks: %w", err)
			}

			fmt.Printf("%-10s %-20s %-15s %-10s %-10s\n", "ID", "Session", "Command", "Status", "Exit Code")
			fmt.Println(strings.Repeat("-", 70))
			for _, t := range tasks {
				cmdPreview := t.Command
				if len(cmdPreview) > 15 {
					cmdPreview = cmdPreview[:15] + "..."
				}
				fmt.Printf("%-10d %-20s %-15s %-10s %-10d\n",
					t.ID,
					t.SessionID[:16],
					cmdPreview,
					t.Status,
					t.ExitCode,
				)
			}

			return nil
		},
	}

	logsCmd := &cobra.Command{
		Use:   "logs",
		Short: "View server logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := commands.NewClient(serverURL, apiKey, "", "")
			logs, err := client.GetLogs(50)
			if err != nil {
				return fmt.Errorf("failed to get logs: %w", err)
			}

			for _, l := range logs {
				fmt.Printf("[%s] [%s] [%s] %s\n",
					l.Timestamp.Format("2006-01-02 15:04:05"),
					l.Level,
					l.Component,
					l.Message,
				)
			}

			return nil
		},
	}

	shellCmd := &cobra.Command{
		Use:   "shell <session_id>",
		Short: "Interactive shell with a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]

			ctx, cancel := context.WithCancel(context.Background())
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

			go func() {
				<-sigChan
				cancel()
			}()

			fmt.Printf("Interactive shell with session %s\n", sessionID)
			fmt.Println("Type 'exit' to quit")

			client := commands.NewClient(serverURL, apiKey, "", "")

			reader := bufio.NewReader(os.Stdin)
			for {
				select {
				case <-ctx.Done():
					return nil
				default:
				}

				fmt.Print("> ")
				line, _ := reader.ReadString('\n')
				line = strings.TrimSpace(line)

				if line == "exit" {
					return nil
				}

				if line == "" {
					continue
				}

				taskID, err := client.InteractSession(sessionID, line, nil, "shell", 30)
				if err != nil {
					fmt.Printf("Error: %v\n", err)
					continue
				}

				time.Sleep(500 * time.Millisecond)

				task, err := client.GetTask(taskID)
				if err != nil {
					fmt.Printf("Error getting result: %v\n", err)
					continue
				}

				fmt.Print(task.Output)
				if task.Error != "" {
					fmt.Printf("Error: %s\n", task.Error)
				}
			}
		},
	}

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(sessionsCmd)
	rootCmd.AddCommand(interactCmd)
	rootCmd.AddCommand(listenersCmd)
	rootCmd.AddCommand(createListenerCmd)
	rootCmd.AddCommand(tasksCmd)
	rootCmd.AddCommand(logsCmd)
	rootCmd.AddCommand(shellCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
