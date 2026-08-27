package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"toshell/internal/common/types"
)

type Client struct {
	serverURL  string
	apiKey     string
	username   string
	token      string
	httpClient *http.Client
}

type LoginResponse struct {
	Token string `json:"token"`
}

func NewClient(serverURL, apiKey, username, token string) *Client {
	return &Client{
		serverURL:  serverURL,
		apiKey:     apiKey,
		username:   username,
		token:      token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) Login(username, password string) error {
	url := fmt.Sprintf("%s/api/v1/login", c.serverURL)

	data := fmt.Sprintf("username=%s&password=%s", username, password)
	req, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var loginResp LoginResponse
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return err
	}

	c.token = loginResp.Token
	return nil
}

func (c *Client) makeRequest(method, path string, body []byte) ([]byte, error) {
	url := c.serverURL + path

	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	} else if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (c *Client) ListSessions() ([]*types.SessionInfo, error) {
	data, err := c.makeRequest("GET", "/api/v1/sessions", nil)
	if err != nil {
		return nil, err
	}

	var response struct {
		Sessions []*types.SessionInfo `json:"sessions"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	return response.Sessions, nil
}

func (c *Client) GetSession(id string) (*types.SessionInfo, error) {
	data, err := c.makeRequest("GET", "/api/v1/sessions/"+id, nil)
	if err != nil {
		return nil, err
	}

	var session types.SessionInfo
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

func (c *Client) DeleteSession(id string) error {
	_, err := c.makeRequest("DELETE", "/api/v1/sessions/"+id, nil)
	return err
}

func (c *Client) InteractSession(id, command string, args []string, executeType string, timeout uint32) (uint64, error) {
	payload := map[string]interface{}{
		"command":      command,
		"args":         args,
		"execute_type": executeType,
		"timeout":      timeout,
	}

	body, _ := json.Marshal(payload)
	data, err := c.makeRequest("POST", "/api/v1/sessions/"+id+"/interact", body)
	if err != nil {
		return 0, err
	}

	var response struct {
		TaskID uint64 `json:"task_id"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return 0, err
	}

	return response.TaskID, nil
}

func (c *Client) ListTasks(sessionID string) ([]*types.TaskInfo, error) {
	path := "/api/v1/tasks"
	if sessionID != "" {
		path += "?session_id=" + sessionID
	}

	data, err := c.makeRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response struct {
		Tasks []*types.TaskInfo `json:"tasks"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	return response.Tasks, nil
}

func (c *Client) GetTask(id uint64) (*types.TaskInfo, error) {
	data, err := c.makeRequest("GET", fmt.Sprintf("/api/v1/tasks/%d", id), nil)
	if err != nil {
		return nil, err
	}

	var task types.TaskInfo
	if err := json.Unmarshal(data, &task); err != nil {
		return nil, err
	}

	return &task, nil
}

func (c *Client) CancelTask(id uint64) error {
	_, err := c.makeRequest("POST", fmt.Sprintf("/api/v1/tasks/%d/cancel", id), nil)
	return err
}

func (c *Client) CreateTask(sessionID, command string, args []string, executeType string, timeout uint32) (uint64, error) {
	payload := map[string]interface{}{
		"session_id":   sessionID,
		"command":      command,
		"args":         args,
		"execute_type": executeType,
		"timeout":      timeout,
	}

	body, _ := json.Marshal(payload)
	data, err := c.makeRequest("POST", "/api/v1/tasks", body)
	if err != nil {
		return 0, err
	}

	var response struct {
		TaskID uint64 `json:"task_id"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return 0, err
	}

	return response.TaskID, nil
}

func (c *Client) ListListeners() ([]*types.ListenerInfo, error) {
	data, err := c.makeRequest("GET", "/api/v1/listeners", nil)
	if err != nil {
		return nil, err
	}

	var response struct {
		Listeners []*types.ListenerInfo `json:"listeners"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	return response.Listeners, nil
}

func (c *Client) CreateListener(name, ltype, bindAddr string, port uint16, certFile, keyFile string) (string, error) {
	payload := map[string]interface{}{
		"name":      name,
		"type":      ltype,
		"bind_addr": bindAddr,
		"port":      port,
	}

	if certFile != "" {
		payload["cert_file"] = certFile
	}
	if keyFile != "" {
		payload["key_file"] = keyFile
	}

	body, _ := json.Marshal(payload)
	data, err := c.makeRequest("POST", "/api/v1/listeners", body)
	if err != nil {
		return "", err
	}

	var response struct {
		ListenerID string `json:"listener_id"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return "", err
	}

	return response.ListenerID, nil
}

func (c *Client) StartListener(id string) error {
	_, err := c.makeRequest("POST", "/api/v1/listeners/"+id+"/start", nil)
	return err
}

func (c *Client) StopListener(id string) error {
	_, err := c.makeRequest("POST", "/api/v1/listeners/"+id+"/stop", nil)
	return err
}

func (c *Client) DeleteListener(id string) error {
	_, err := c.makeRequest("DELETE", "/api/v1/listeners/"+id, nil)
	return err
}

func (c *Client) GetLogs(limit int) ([]*types.LogEntry, error) {
	path := fmt.Sprintf("/api/v1/logs?limit=%d", limit)
	data, err := c.makeRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response struct {
		Logs []*types.LogEntry `json:"logs"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	return response.Logs, nil
}

func (c *Client) Health() error {
	url := c.serverURL + "/api/v1/health"
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed with status: %d", resp.StatusCode)
	}

	return nil
}

// ListProcesses 列出进程
func (c *Client) ListProcesses(sessionID string) (uint64, error) {
	data, err := c.makeRequest("GET", "/api/v1/sessions/"+sessionID+"/processes", nil)
	if err != nil {
		return 0, err
	}

	var response struct {
		TaskID uint64 `json:"task_id"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return 0, err
	}

	return response.TaskID, nil
}

// KillProcess 终止进程
func (c *Client) KillProcess(sessionID string, pid uint32) (uint64, error) {
	data, err := c.makeRequest("DELETE", fmt.Sprintf("/api/v1/sessions/%s/processes/%d", sessionID, pid), nil)
	if err != nil {
		return 0, err
	}

	var response struct {
		TaskID uint64 `json:"task_id"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return 0, err
	}

	return response.TaskID, nil
}

func GetServerURL() string {
	url := os.Getenv("TOSHELL_SERVER")
	if url == "" {
		url = "http://localhost:8081"
	}
	return url
}

func GetAPIKey() string {
	return os.Getenv("TOSHELL_API_KEY")
}
