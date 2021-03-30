package storage

import "errors"

var (
	ErrRecordNotFound = errors.New("record not found")
	ErrDuplicateEntry = errors.New("duplicate entry")
	ErrCardIsInvalid  = errors.New("card information is invalid")
)
