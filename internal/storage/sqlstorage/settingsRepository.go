package sqlstorage

import (
	"database/sql"
	"gc-backend/internal/model"
	"gc-backend/internal/storage"
	"time"
)

type SettingsRepository struct {
	storage *Storage
}

func (r *SettingsRepository) Create(projectId int, id string, ident string, name string, visualOptions string) error {
	var ProjectID int
	if err := r.storage.db.QueryRow(
		"INSERT INTO \"settings\" (project_id, id, ident, name, settings,created_at, is_active) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (project_id) DO UPDATE "+
			"set id = excluded.id, ident = excluded.ident, "+
			"name = excluded.name, settings = excluded.settings, "+
			"created_at = excluded.created_at RETURNING project_id",
		projectId, id, ident, name, visualOptions, time.Now(), true,
	).Scan(&ProjectID); err != nil {
		return storage.ErrDuplicateEntry
	}

	return nil
}

func (r *SettingsRepository) FindByProject(projectId int) (*model.Settings, error) {

	setting := &model.Settings{}
	if err := r.storage.db.QueryRow(
		"SELECT project_id, id, ident, name, settings FROM \"settings\" WHERE is_active = $1 AND project_id = $2",
		true,
		projectId,
	).Scan(&setting.ProjectID, &setting.Id, &setting.Ident, &setting.Name, &setting.SettingString); err != nil {
		if err == sql.ErrNoRows {
			return nil, storage.ErrRecordNotFound
		}
		return nil, err
	}

	return setting, nil
}
