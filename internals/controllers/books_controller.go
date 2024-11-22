package controllers

import (
	"fmt"
	"library-management/internals/models"
	"library-management/internals/repository"
	logger "library-management/loggers"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type BookRequest struct {
	IsBn            string  `json:"isbn"`
	Title           string  `json:"title"`
	Subtitle        string  `json:"subtitle"`
	Publisher       string  `json:"publisher"`
	PublicationYear int64   `json:"publication_year"`
	Edition         string  `json:"edition"`
	Language        string  `json:"language"`
	TotalCopies     int64   `json:"total_copies"`
	AvailableCopies int64   `json:"available_copies"`
	Price           float64 `json:"price"`
}

type BookResponse struct {
	IsBn            string  `json:"isbn"`
	Title           string  `json:"title"`
	Subtitle        string  `json:"subtitle"`
	Publisher       string  `json:"publisher"`
	PublicationYear int64   `json:"publication_year"`
	Edition         string  `json:"edition"`
	Language        string  `json:"language"`
	TotalCopies     int64   `json:"total_copies"`
	AvailableCopies int64   `json:"available_copies"`
	Price           float64 `json:"price"`
}

func AddBook(c *gin.Context) {
	var book BookRequest
	errJson := c.BindJSON(&book)
	if errJson != nil {
		logger.Logger.Error("failed to bind request , invalid request format")
		c.AbortWithError(400, errJson)
	}

	book.AddBookDetails()

}

func (book *BookRequest) AddBookDetails() {
	requestBook := models.BookModels{
		IsBn:            book.IsBn,
		Title:           book.Title,
		Subtitle:        &book.Subtitle,
		Publisher:       book.Publisher,
		Edition:         &book.Edition,
		PublicationYear: int(book.PublicationYear),
		Language:        book.Language,
		TotalCopies:     int(book.TotalCopies),
		AvailableCopies: int(book.AvailableCopies),
		Price:           book.Price,
	}
	err := repository.AddBookDetails(requestBook)
	if err != nil {
		logger.Logger.Error("Failed to add books :", err)
		return
	}

}
func GetBookByBookId(c *gin.Context) {
	idStr := c.Query("book_id")
	id, e := strconv.Atoi(idStr)
	if e != nil {
		logger.Logger.Error(" failed to convert string to interger : ", e)
	}
	bookDetails, err := repository.GetBookDetailsById(id)
	if err != nil {
		logger.Logger.Error("failed to get book details :", err)
	}
	fmt.Println("book :", bookDetails)
	response := convertBookModelToResponse(bookDetails)
	c.JSON(http.StatusOK, response)
}

func GetAll(c *gin.Context) {
	books, err := repository.GetAllBooks()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to fetch book details",
		})
		return
	}
	// creating slice using make
	bookresponse := make([]*BookResponse, 0, len(books))
	for _, bookDetails := range books {
		response := convertBookModelToResponse(&bookDetails)
		bookresponse = append(bookresponse, response)
	}
	c.JSON(http.StatusOK, bookresponse)
}

func convertBookModelToResponse(bookDetails *models.BookModels) *BookResponse {
	return &BookResponse{
		IsBn:            bookDetails.IsBn,
		Title:           bookDetails.Title,
		Subtitle:        *bookDetails.Subtitle,
		PublicationYear: int64(bookDetails.PublicationYear),
		Publisher:       bookDetails.Publisher,
		Edition:         *bookDetails.Edition,
		Language:        bookDetails.Language,
		Price:           bookDetails.Price,
		TotalCopies:     int64(bookDetails.TotalCopies),
		AvailableCopies: int64(bookDetails.AvailableCopies),
	}
}
