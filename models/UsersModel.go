package models

import (
	"time"
)

// defining the schema
type UserProfile struct {
	ID           uint      `gorm :"primaryKey"`
	FirstName    string    `gorm:"not null;column:first_name"`
	LastName     string    `gorm:"not null;column:last_name"`
	Email        string    `gorm:"not null;unique;column:email"`
	Password     string    `gorm:"not null;column:password"`
	Phone        string    `gorm:"column:phone"`
	AddressLine1 string    `gorm:"column:address_line1"`
	AddressLine2 string    `gorm:"column:address_line2"`
	City         string    `gorm:"column:city"`
	State        string    `gorm:"column:state"`
	Country      string    `gorm:"column:country"`
	ZipCode      string    `gorm:"column:zip_code"`
	UserType     string    `gorm:"not null;check:user_type IN ('student', 'faculty', 'staff');column:user_type"`
	CreatedAt    time.Time `gorm:"autoUpdateTime;column:created_at"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime;column:updated_at"`
}
