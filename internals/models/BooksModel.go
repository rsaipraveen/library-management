package models

import "time"

type BookModels struct {
	Id              uint      `gorm:"primaryKey;column:id;type:uuid;"`
	IsBn            string    `gorm:"column:isbn ; type:varchar(20);unique;not null "`
	Title           string    `gorm:"column:title;type:varchar(255); not null "`
	Subtitle        *string   `gorm:"column:subtitle; type:varchar(255)"`
	Publisher       string    `gorm:"column:publisher; type:varchar(255); not null "`
	PublicationYear int       `gorm:"column:publication_year;type:integer; not null"`
	Edition         *string   `gorm:"column:edition; type: varchar(50)"`
	Language        string    `gorm:"column:language; type:varchar(20)"`
	TotalCopies     int       `gorm:"column:total_copies; type:integer ; not null"`
	AvailableCopies int       `gorm:"column:available_copies; type:integer; not null"`
	Price           float64   `gorm:"column:price;type:float; not null"`
	CreatedAt       time.Time `gorm:"autoUpdateTime;column:created_at"`
	UpdatedAt       time.Time `gorm:"autoUpdateTime;column:updated_at"`
}
