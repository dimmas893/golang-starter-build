package models

// SecurityAsymmetricKey struct represents the security_asymmetric_key table
type SecurityAsymmetricKey struct {
	ID         uint   `gorm:"primaryKey"`
	APIKey     string `gorm:"unique;not null" validate:"required"`
	PrivateKey string `gorm:"type:text;not null" validate:"required"`
	PublicKey  string `gorm:"type:text;not null" validate:"required"`
	Secret     string `gorm:"type:text;not null" validate:"required"`
}
