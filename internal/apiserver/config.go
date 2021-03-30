package apiserver

type Config struct {
	BindAddress string `toml:"bind_addr"`
	LogLevel    string `toml:"log_level"`
	DatabaseURL string `toml:"database_url"`
	SessionKey  string `toml:"session_key"`
}

func NewConfig() *Config {
	return &Config{
		BindAddress: ":8080",
		LogLevel:    "debug",
	}
}
