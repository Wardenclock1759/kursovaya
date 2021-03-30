package model

type Settings struct {
	SettingString string `json:"visualOptions"`
	ProjectID     int    `json:"project_id"`
	Id            string `json:"id"`
	Ident         string `json:"ident"`
	Name          string `json:"name"`
}
