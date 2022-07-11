package data

type ElasticIPAttachment struct {
	// Primilary key in elastic_ip_attachments table
	ID            int
	AccountID     string
	Region        string
	AssociationID string
}
