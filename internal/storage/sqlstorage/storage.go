package sqlstorage

import (
	"database/sql"
	"gc-backend/internal/storage"

	_ "github.com/lib/pq"
)

type Storage struct {
	db                 *sql.DB
	projectRepository  *ProjectRepository
	settingsRepository *SettingsRepository
}

func New(db *sql.DB) *Storage {
	return &Storage{
		db: db,
	}
}

func (s *Storage) Project() storage.ProjectRepository {
	if s.projectRepository != nil {
		return s.projectRepository
	}

	s.projectRepository = &ProjectRepository{
		storage: s,
	}

	return s.projectRepository
}

func (s *Storage) Settings() storage.SettingsRepository {
	if s.settingsRepository != nil {
		return s.settingsRepository
	}

	s.settingsRepository = &SettingsRepository{
		storage: s,
	}

	return s.settingsRepository
}
