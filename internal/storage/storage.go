package storage

type Storage interface {
	Project() ProjectRepository
	Settings() SettingsRepository
}
