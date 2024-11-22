package repository

import (
	"errors"
	"fmt"
	"library-management/initializers"
	"library-management/internals/models"
	logger "library-management/loggers"

	"gorm.io/gorm"
)

type BookRepository interface {
	Create(book *models.BookModels)
	Update(book *models.BookModels) (*models.BookModels, error)
	Delete(book *models.BookModels)
	FindById(id int) (*models.BookModels, error)
	FindAll() ([]*models.BookModels, error)
}

type bookrepo struct {
	db *gorm.DB
}

func AddBookDetails(book models.BookModels) error {
	fmt.Println("inside add book details repository ")
	result := initializers.DB.Create(&book)
	if result.Error != nil {
		logger.Logger.Error("error while inserting book details into books databse :", result.Error)
	}
	return nil
}

func GetBookDetailsById(id int) (*models.BookModels, error) {
	var book models.BookModels
	result := initializers.DB.First(&book, id)
	if result.Error != nil {
		fmt.Println("failed to fetch book details :", book)

		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		logger.Logger.Error(" invalid book id ")
		return nil, errors.New("no rows affected")
	}

	return &book, nil
}

func GetAllBooks() ([]models.BookModels, error) {
	var books []models.BookModels
	result := initializers.DB.Find(&books)

	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, errors.New("no books found ")
	}
	return books, nil
}
