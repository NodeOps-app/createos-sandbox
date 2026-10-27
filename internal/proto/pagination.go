package proto

// Pagination is the metadata shared by every paginated public API response.
type Pagination struct {
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
	Count  int `json:"count"`
}

// Page is the data payload inside a paginated JSend success envelope.
type Page[T any] struct {
	Data       T          `json:"data"`
	Pagination Pagination `json:"pagination"`
}
