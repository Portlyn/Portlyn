package store

import "errors"

var ErrNotFound = errors.New("resource not found")
var ErrConflict = errors.New("resource conflict")
var ErrAlreadyUsed = errors.New("resource already used")
var ErrStale = errors.New("resource changed concurrently")
