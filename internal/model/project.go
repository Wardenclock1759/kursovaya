package model

import (
	validation "github.com/go-ozzo/ozzo-validation"
	"time"
)

type Project struct {
	ApiKey    string    `json:"api_key"`
	ProjectID int       `json:"project_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	IsActive  bool      `json:"is_active"`
}

func (p *Project) Validate() error {
	return validation.ValidateStruct(
		p,
		validation.Field(&p.ApiKey, validation.Required, validation.Length(1, 255)),
		validation.Field(&p.ProjectID, validation.Required),
	)
}

func (p *Project) BeforeCreate() error {
	p.CreatedAt = time.Now()
	p.IsActive = true
	return nil
}
