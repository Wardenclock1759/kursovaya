package storage

import (
	"gc-backend/internal/model"
)

type ProjectRepository interface {
	Create(*model.Project) error
	FindByAll(string, int) (*model.Project, error)
	DeleteByAll(string, int) error
}

type SettingsRepository interface {
	Create(int, string, string, string, string) error
	FindByProject(int) (*model.Settings, error)
}
