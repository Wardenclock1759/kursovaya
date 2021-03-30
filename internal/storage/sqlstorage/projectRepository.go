package sqlstorage

import (
	"database/sql"
	"gc-backend/internal/model"
	"gc-backend/internal/storage"
)

type ProjectRepository struct {
	storage *Storage
}

func (r *ProjectRepository) Create(p *model.Project) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := p.BeforeCreate(); err != nil {
		return err
	}

	if err := r.storage.db.QueryRow(
		"INSERT INTO \"project\" (api_key, project_id, created_at, is_active) VALUES ($1, $2, $3, $4) RETURNING is_active",
		p.ApiKey,
		p.ProjectID,
		p.CreatedAt,
		p.IsActive,
	).Scan(&p.IsActive); err != nil {
		return storage.ErrDuplicateEntry
	}

	return nil
}

func (r *ProjectRepository) FindByAll(apiKey string, projectID int) (*model.Project, error) {
	p := &model.Project{}
	if err := r.storage.db.QueryRow(
		"SELECT api_key, project_id, created_at, is_active FROM \"project\" WHERE is_active = $1 AND project_id = $2 AND api_key = $3",
		true,
		projectID,
		apiKey,
	).Scan(&p.ApiKey, &p.ProjectID, &p.CreatedAt, &p.IsActive); err != nil {
		if err == sql.ErrNoRows {
			return nil, storage.ErrRecordNotFound
		}
		return nil, err
	}

	return p, nil
}

func (r *ProjectRepository) DeleteByAll(apiKey string, projectID int) error {
	p := &model.Project{}
	if err := r.storage.db.QueryRow(
		"UPDATE \"project\" SET is_active = $1 WHERE is_active = $2 AND project_id = $3 AND api_key = $4 RETURNING is_active",
		false,
		true,
		projectID,
		apiKey,
	).Scan(&p.IsActive); err != nil {
		if err == sql.ErrNoRows {
			return storage.ErrRecordNotFound
		}
		return err
	}

	return nil
}
