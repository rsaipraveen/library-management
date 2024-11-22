package service

import "library-management/internals/controllers"

type BookServices interface {
	AddBookDetails(book *controllers.BookRequest) (controllers.BookResponse, error)
	UpdateBookDetails(book *controllers.BookRequest)
	ReadBookDetails(book *controllers.BookRequest)
	DeleteBookDetails(book *controllers.BookRequest)
	GetAllBooks() ([]controllers.BookResponse, error)
}

// type bookService struct {
// }
