package main

import (
	"encoding/json"
	"net/http"

	"github.com/box-extruder/dast/internal/enterprise/docker"
)

func (h *Handler) handleContainerStatus(w http.ResponseWriter, r *http.Request) {
	monitor, err := docker.NewMonitor(nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer monitor.Close()

	statuses, err := monitor.GetContainersStatus(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statuses)
}

func (h *Handler) handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	monitor, err := docker.NewMonitor(nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer monitor.Close()

	logs, err := monitor.GetContainerLogs(r.Context(), name, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"logs": logs})
}
